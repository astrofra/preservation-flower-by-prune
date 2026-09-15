/*
 * nX/X3 engine asset extractor. No third-party dependencies.
 * The FXLK reader was reconstructed from FreeStyle (2000). External-table
 * modes support the earlier LTP3 (1999) data file and Dash (1999) GCR file.
 * See documentation/dash-container-format.md for evidence and limitations.
 *
 * cmake -S . -B build -G "Visual Studio 17 2022" -A x64
 * cmake --build build --config Release
 * bin\klx_unpack.exe archive.klx new-output-directory
 * bin\klx_unpack.exe --list archive.klx
 * bin\klx_unpack.exe --ltp3-exe LTP3.exe data new-output-directory
 * bin\klx_unpack.exe --list --ltp3-exe LTP3.exe data
 * bin\klx_unpack.exe --dash-exe Dash.exe Dash.GCR new-output-directory
 * bin\klx_unpack.exe --list --dash-exe Dash.exe Dash.GCR
 */
#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#endif
#ifndef _WIN32
#define _POSIX_C_SOURCE 200809L
#endif

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <direct.h>
#include <fcntl.h>
#include <io.h>
#include <share.h>
#include <wchar.h>
#else
#include <fcntl.h>
#include <sys/types.h>
#include <unistd.h>
#endif

#define SIZE_LIMIT ((size_t)256 * 1024 * 1024)
#define WINDOW 4096u
#define MATCH_MAX 60u
#define SYMBOLS 314u
#define Q1 0x8000u
#define Q2 0x10000u
#define Q3 0x18000u
#define Q4 0x20000u
#define LTP3_TABLE_RVA 0x00027030u
#define LTP3_ENTRY_COUNT 157u
#define DASH_TABLE_RVA 0x00017030u
#define DASH_ENTRY_COUNT 98u

enum StorageMethod {
    METHOD_XOR_9A,
    METHOD_LZARI,
    METHOD_RAW
};

typedef struct Decoder {
    const unsigned char *input;
    size_t input_size, bit_position;
    uint32_t low, high, value;
    uint32_t frequency[SYMBOLS + 1], cumulative[SYMBOLS + 1];
    uint32_t positions[WINDOW + 1];
    unsigned int symbol_to_char[SYMBOLS + 1];
    unsigned char window[WINDOW];
    int failed;
} Decoder;

typedef struct Entry {
    char *name;                 /* Original Windows-1252 name. */
    char *relative;             /* Validated Windows-1252 path without drive colon. */
    char *path;                 /* Same relative path, UTF-8. */
    uint32_t size, stored;
    size_t offset;
    enum StorageMethod method;
    unsigned char *decoded;
} Entry;

typedef struct PeImage {
    const unsigned char *data;
    size_t size, section_table;
    uint32_t image_base, size_of_headers;
    uint16_t section_count;
} PeImage;

static void *allocate(size_t size)
{
    void *p = malloc(size ? size : 1);
    if (!p) {
        fprintf(stderr, "error: out of memory\n");
        exit(1);
    }
    return p;
}

static char *copy_string(const char *s)
{
    size_t size = strlen(s) + 1;
    char *p = (char *)allocate(size);
    memcpy(p, s, size);
    return p;
}

static uint32_t le32(const unsigned char *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 |
           (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

static uint16_t le16(const unsigned char *p)
{
    return (uint16_t)((uint16_t)p[0] | (uint16_t)p[1] << 8);
}

#ifdef _WIN32
static wchar_t *wide_path(const char *path)
{
    int count = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path, -1, NULL, 0);
    wchar_t *result;
    if (!count) return NULL;
    result = (wchar_t *)allocate((size_t)count * sizeof(*result));
    if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path, -1, result, count)) {
        free(result);
        return NULL;
    }
    return result;
}
#endif

static FILE *open_file(const char *path, int write)
{
#ifdef _WIN32
    wchar_t *wide = wide_path(path);
    FILE *file;
    if (!wide) return NULL;
    if (write) {
        int descriptor;
        if (_wsopen_s(&descriptor, wide, _O_WRONLY | _O_CREAT | _O_EXCL | _O_BINARY,
                      _SH_DENYRW, _S_IREAD | _S_IWRITE)) {
            free(wide);
            return NULL;
        }
        file = _fdopen(descriptor, "wb");
        if (!file) { _close(descriptor); _wremove(wide); }
    } else file = _wfopen(wide, L"rb");
    free(wide);
    return file;
#else
    if (write) {
        int descriptor = open(path, O_WRONLY | O_CREAT | O_EXCL, 0644);
        FILE *file;
        if (descriptor < 0) return NULL;
        file = fdopen(descriptor, "wb");
        if (!file) { close(descriptor); remove(path); }
        return file;
    }
    return fopen(path, "rb");
#endif
}

static void remove_created_file(const char *path)
{
#ifdef _WIN32
    wchar_t *wide = wide_path(path);
    if (wide) { _wremove(wide); free(wide); }
#else
    remove(path);
#endif
}

/* 0: absent; 1: ordinary directory; 2: anything else (including links). */
static int path_kind(const char *path)
{
#ifdef _WIN32
    wchar_t *wide = wide_path(path);
    DWORD attributes;
    DWORD error;
    if (!wide) return 2;
    attributes = GetFileAttributesW(wide);
    error = attributes == INVALID_FILE_ATTRIBUTES ? GetLastError() : ERROR_SUCCESS;
    free(wide);
    if (attributes == INVALID_FILE_ATTRIBUTES) {
        return error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND ? 0 : 2;
    }
    if (attributes & FILE_ATTRIBUTE_REPARSE_POINT) return 2;
    return attributes & FILE_ATTRIBUTE_DIRECTORY ? 1 : 2;
#else
    struct stat info;
    if (lstat(path, &info)) return errno == ENOENT ? 0 : 2;
    return S_ISDIR(info.st_mode) ? 1 : 2;
#endif
}

static int make_directory(const char *path)
{
#ifdef _WIN32
    wchar_t *wide = wide_path(path);
    int result;
    if (!wide) return 0;
    result = _wmkdir(wide);
    free(wide);
#else
    int result = mkdir(path, 0755);
#endif
    return result == 0;
}

static int make_tree(const char *path)
{
    char *copy = copy_string(path);
    size_t i, length = strlen(copy);
    int ok = 1;
    for (i = 1; i <= length; ++i) {
        char saved = copy[i];
        if (saved != '/' && saved != '\\' && saved != '\0') continue;
        if (i == 2 && copy[1] == ':') continue;
        copy[i] = '\0';
        if (path_kind(copy) != 1 && !make_directory(copy)) ok = 0;
        copy[i] = saved;
        if (!ok) break;
    }
    free(copy);
    return ok;
}

static unsigned char *read_file(const char *path, size_t *size)
{
    FILE *file = open_file(path, 0);
    long length;
    unsigned char *data;
    if (!file) return NULL;
    if (fseek(file, 0, SEEK_END) || (length = ftell(file)) < 0 ||
        (size_t)length > SIZE_LIMIT || fseek(file, 0, SEEK_SET)) {
        fclose(file);
        return NULL;
    }
    *size = (size_t)length;
    data = (unsigned char *)allocate(*size);
    if (fread(data, 1, *size, file) != *size) {
        free(data);
        fclose(file);
        return NULL;
    }
    fclose(file);
    return data;
}

static unsigned int get_bit(Decoder *d)
{
    size_t offset = d->bit_position / 8;
    unsigned int shift = 7u - (unsigned int)(d->bit_position % 8);
    ++d->bit_position;
    if (offset >= d->input_size) {
        /* Bounded zero lookahead for arithmetic termination. */
        if (offset - d->input_size >= 2) d->failed = 1;
        return 0;
    }
    return (d->input[offset] >> shift) & 1u;
}

static unsigned int decode_symbol(Decoder *d, const uint32_t *cum, unsigned int count)
{
    uint32_t width = d->high - d->low;
    uint32_t target;
    unsigned int left = 1, right = count, symbol;
    if (d->high <= d->low || d->value < d->low || d->value >= d->high) {
        d->failed = 1;
        return 1;
    }
    target = (uint32_t)(((uint64_t)(d->value - d->low + 1u) * cum[0] - 1u) / width);
    while (left < right) {
        unsigned int middle = (left + right) / 2;
        if (cum[middle] > target) left = middle + 1;
        else right = middle;
    }
    symbol = left;
    d->high = d->low + (uint32_t)((uint64_t)width * cum[symbol - 1] / cum[0]);
    d->low += (uint32_t)((uint64_t)width * cum[symbol] / cum[0]);
    while (!d->failed) {
        if (d->low >= Q2) {
            d->low -= Q2; d->high -= Q2; d->value -= Q2;
        } else if (d->low >= Q1 && d->high <= Q3) {
            d->low -= Q1; d->high -= Q1; d->value -= Q1;
        } else if (d->high > Q2) {
            break;
        }
        d->low *= 2; d->high *= 2;
        d->value = d->value * 2 + get_bit(d);
    }
    return symbol;
}

static void update_model(Decoder *d, unsigned int symbol)
{
    unsigned int i;
    if (d->cumulative[0] >= 0x7fffu) {
        uint32_t total = 0;
        for (i = SYMBOLS; i > 0; --i) {
            d->cumulative[i] = total;
            d->frequency[i] = (d->frequency[i] + 1) / 2;
            total += d->frequency[i];
        }
        d->cumulative[0] = total;
    }
    i = symbol;
    while (i > 1 && d->frequency[i] == d->frequency[i - 1]) --i;
    if (i != symbol) {
        unsigned int tmp = d->symbol_to_char[i];
        d->symbol_to_char[i] = d->symbol_to_char[symbol];
        d->symbol_to_char[symbol] = tmp;
    }
    ++d->frequency[i];
    while (i > 0) ++d->cumulative[--i];
}

static int decode_lzari(const unsigned char *input, size_t stored,
                        unsigned char *output, size_t size)
{
    Decoder *d = (Decoder *)allocate(sizeof(*d));
    unsigned int i, cursor = WINDOW - MATCH_MAX;
    size_t written = 0;
    int ok;
    memset(d, 0, sizeof(*d));
    d->input = input; d->input_size = stored; d->high = Q4;
    memset(d->window, ' ', WINDOW - MATCH_MAX);
    for (i = 1; i <= SYMBOLS; ++i) {
        d->frequency[i] = 1;
        d->symbol_to_char[i] = i - 1;
    }
    for (i = 0; i <= SYMBOLS; ++i) d->cumulative[i] = SYMBOLS - i;
    for (i = WINDOW; i > 0; --i) d->positions[i - 1] = d->positions[i] + 10000u / (i + 200u);
    if (size) for (i = 0; i < 17; ++i) d->value = d->value * 2 + get_bit(d);
    while (written < size && !d->failed) {
        unsigned int symbol = decode_symbol(d, d->cumulative, SYMBOLS);
        unsigned int ch = d->symbol_to_char[symbol];
        update_model(d, symbol);
        if (ch < 256) {
            output[written++] = (unsigned char)ch;
            d->window[cursor] = (unsigned char)ch;
            cursor = (cursor + 1) & (WINDOW - 1);
        } else {
            unsigned int distance = decode_symbol(d, d->positions, WINDOW);
            unsigned int source = (cursor + WINDOW - distance) & (WINDOW - 1);
            unsigned int length = ch - 253u;
            if (length > size - written) { d->failed = 1; break; }
            for (i = 0; i < length; ++i) {
                unsigned char byte = d->window[(source + i) & (WINDOW - 1)];
                output[written++] = byte;
                d->window[cursor] = byte;
                cursor = (cursor + 1) & (WINDOW - 1);
            }
        }
    }
    ok = !d->failed && written == size;
    free(d);
    return ok;
}

static unsigned int lower_1252(unsigned int c)
{
    if ((c >= 'A' && c <= 'Z') || (c >= 0xc0 && c <= 0xde && c != 0xd7)) return c + 32;
    if (c == 0x8a || c == 0x8c || c == 0x8e) return c + 16;
    if (c == 0x9f) return 0xff;
    return c;
}

static int equal_n(const char *a, const char *b, size_t n)
{
    size_t i;
    for (i = 0; i < n; ++i)
        if (lower_1252((unsigned char)a[i]) != lower_1252((unsigned char)b[i])) return 0;
    return 1;
}

static int valid_component(const char *s, size_t length)
{
    size_t i, stem = 0;
    if (!length || s[length - 1] == '.' || s[length - 1] == ' ') return 0;
    for (i = 0; i < length; ++i) {
        unsigned char c = (unsigned char)s[i];
        if (c < 32 || c == 127 || strchr("<>:\"|?*", c)) return 0;
    }
    while (stem < length && s[stem] != '.') ++stem;
    if (stem == 3 && (equal_n(s, "con", 3) || equal_n(s, "prn", 3) ||
                     equal_n(s, "aux", 3) || equal_n(s, "nul", 3))) return 0;
    if (stem == 4 && (equal_n(s, "com", 3) || equal_n(s, "lpt", 3)) &&
        s[3] >= '1' && s[3] <= '9') return 0;
    return 1;
}

static char *normalize_name(const char *name)
{
    char *path = copy_string(name);
    size_t i, start = 0, length = strlen(path);
    for (i = 0; i < length; ++i) if (path[i] == '\\') path[i] = '/';
    if (length >= 3 && path[1] == ':' && path[2] == '/' &&
        lower_1252((unsigned char)path[0]) >= 'a' && lower_1252((unsigned char)path[0]) <= 'z') {
        path[0] = (char)(lower_1252((unsigned char)path[0]) - 32);
        memmove(path + 1, path + 2, length - 1);
        --length;
    }
    for (i = 0; i <= length; ++i) {
        if (path[i] != '/' && path[i] != '\0') continue;
        if (!valid_component(path + start, i - start)) { free(path); return NULL; }
        start = i + 1;
    }
    return path;
}

static char *utf8_from_1252(const char *text)
{
    static const uint16_t special[32] = {
        0x20ac,0x0081,0x201a,0x0192,0x201e,0x2026,0x2020,0x2021,
        0x02c6,0x2030,0x0160,0x2039,0x0152,0x008d,0x017d,0x008f,
        0x0090,0x2018,0x2019,0x201c,0x201d,0x2022,0x2013,0x2014,
        0x02dc,0x2122,0x0161,0x203a,0x0153,0x009d,0x017e,0x0178
    };
    char *result = (char *)allocate(strlen(text) * 3 + 1), *out = result;
    while (*text) {
        uint32_t c = (unsigned char)*text++;
        if (c >= 0x80 && c < 0xa0) c = special[c - 0x80];
        if (c < 0x80) *out++ = (char)c;
        else if (c < 0x800) {
            *out++ = (char)(0xc0 | (c >> 6)); *out++ = (char)(0x80 | (c & 63));
        } else {
            *out++ = (char)(0xe0 | (c >> 12));
            *out++ = (char)(0x80 | ((c >> 6) & 63)); *out++ = (char)(0x80 | (c & 63));
        }
    }
    *out = '\0';
    return result;
}

static void free_entries(Entry *entries, size_t count)
{
    size_t i;
    for (i = 0; i < count; ++i) {
        free(entries[i].name); free(entries[i].relative);
        free(entries[i].path); free(entries[i].decoded);
    }
    free(entries);
}

static const char *method_name(enum StorageMethod method)
{
    if (method == METHOD_XOR_9A) return "xor-9a";
    if (method == METHOD_LZARI) return "lzari";
    return "raw";
}

static int prepare_entry_path(Entry *entries, size_t count)
{
    Entry *e = &entries[count - 1];
    size_t j;
    e->relative = normalize_name(e->name);
    if (!e->relative) return 0;
    e->path = utf8_from_1252(e->relative);
    for (j = 0; j + 1 < count; ++j) {
        size_t a = strlen(e->relative), b = strlen(entries[j].relative);
        size_t n = a < b ? a : b;
        if (equal_n(e->relative, entries[j].relative, n) &&
            (a == b || e->relative[n] == '/' || entries[j].relative[n] == '/')) return 0;
    }
    return 1;
}

static int parse_archive(const unsigned char *data, size_t size, Entry **result, size_t *count)
{
    uint32_t index_size, stored_index;
    unsigned char *index;
    size_t cursor = 0, offset, total = 0, capacity = 0;
    Entry *entries = NULL;
    int ok = 0;
    *count = 0; *result = NULL;
    if (size < 12 || memcmp(data, "FXLK", 4)) {
        fprintf(stderr, "error: expected an FXLK archive header\n"); return 0;
    }
    index_size = le32(data + 4); stored_index = le32(data + 8);
    if (!index_size || index_size > SIZE_LIMIT || !stored_index || stored_index > size - 12) {
        fprintf(stderr, "error: invalid index sizes\n"); return 0;
    }
    offset = 12 + (size_t)stored_index;
    index = (unsigned char *)allocate(index_size);
    if (!decode_lzari(data + 12, stored_index, index, index_size)) goto done;
    while (cursor < index_size) {
        const unsigned char *end = (const unsigned char *)memchr(index + cursor, 0, index_size - cursor);
        size_t length;
        Entry *e;
        if (!end || end == index + cursor || (size_t)(index + index_size - end) < 9) goto done;
        length = (size_t)(end - index - cursor);
        if (length > 4096 || *count >= 100000) goto done;
        if (*count == capacity) {
            Entry *grown;
            capacity = capacity ? capacity * 2 : 64;
            grown = (Entry *)realloc(entries, capacity * sizeof(*entries));
            if (!grown) goto done;
            entries = grown;
        }
        e = &entries[(*count)++];
        memset(e, 0, sizeof(*e));
        e->name = (char *)allocate(length + 1);
        memcpy(e->name, index + cursor, length + 1);
        e->size = le32(end + 1); e->stored = le32(end + 5); e->offset = offset;
        e->method = e->size == e->stored ? METHOD_XOR_9A : METHOD_LZARI;
        cursor += length + 9;
        if (e->size > SIZE_LIMIT - total || e->stored > size - offset ||
            (e->size && !e->stored)) goto done;
        total += e->size; offset += e->stored;
        if (!prepare_entry_path(entries, *count)) goto done;
    }
    if (offset != size) goto done;
    ok = 1;
done:
    free(index);
    if (!ok) {
        fprintf(stderr, "error: malformed index, unsafe/duplicate path, or inconsistent archive sizes\n");
        free_entries(entries, *count); *count = 0;
    } else *result = entries;
    return ok;
}

static int init_pe(PeImage *pe, const unsigned char *data, size_t size)
{
    size_t nt, optional, section_table;
    uint16_t optional_size;
    if (size < 0x40 || data[0] != 'M' || data[1] != 'Z') return 0;
    nt = le32(data + 0x3c);
    if (nt > size - 24 || memcmp(data + nt, "PE\0\0", 4)) return 0;
    optional_size = le16(data + nt + 20);
    optional = nt + 24;
    if (optional_size < 64 || optional > size - optional_size || le16(data + optional) != 0x10b) return 0;
    section_table = optional + optional_size;
    pe->section_count = le16(data + nt + 6);
    if (!pe->section_count || pe->section_count > 96 ||
        section_table > size || (size - section_table) / 40 < pe->section_count) return 0;
    pe->data = data;
    pe->size = size;
    pe->section_table = section_table;
    pe->image_base = le32(data + optional + 28);
    pe->size_of_headers = le32(data + optional + 60);
    return pe->image_base != 0;
}

static int pe_map_rva(const PeImage *pe, uint32_t rva,
                      const unsigned char **result, size_t *available)
{
    unsigned int i;
    if (rva < pe->size_of_headers && rva < pe->size) {
        *result = pe->data + rva;
        *available = pe->size - rva;
        return 1;
    }
    for (i = 0; i < pe->section_count; ++i) {
        const unsigned char *section = pe->data + pe->section_table + i * 40u;
        uint32_t virtual_size = le32(section + 8);
        uint32_t virtual_address = le32(section + 12);
        uint32_t raw_size = le32(section + 16);
        uint32_t raw_offset = le32(section + 20);
        uint32_t span = virtual_size > raw_size ? virtual_size : raw_size;
        uint32_t delta;
        if (rva < virtual_address || rva - virtual_address >= span) continue;
        delta = rva - virtual_address;
        if (delta >= raw_size || raw_offset > pe->size || delta > pe->size - raw_offset) return 0;
        *result = pe->data + raw_offset + delta;
        *available = raw_size - delta;
        if (*available > pe->size - raw_offset - delta) *available = pe->size - raw_offset - delta;
        return 1;
    }
    return 0;
}

static int parse_external_archive(const unsigned char *data, size_t size,
                                  const unsigned char *exe, size_t exe_size,
                                  uint32_t table_rva, size_t entry_count,
                                  const char *path_prefix, const char *format_name,
                                  Entry **result, size_t *count)
{
    PeImage pe;
    Entry *entries = NULL;
    size_t offset = 0, total = 0, i;
    int ok = 0;
    *count = 0;
    *result = NULL;
    if (!init_pe(&pe, exe, exe_size)) {
        fprintf(stderr, "error: invalid 32-bit PE metadata executable\n");
        return 0;
    }
    entries = (Entry *)calloc(entry_count, sizeof(*entries));
    if (!entries) {
        fprintf(stderr, "error: out of memory\n");
        return 0;
    }
    for (i = 0; i < entry_count; ++i) {
        const unsigned char *record, *name_data, *end;
        size_t record_available, name_available, length;
        uint32_t name_va, compressed, record_size, name_rva;
        Entry *e = &entries[i];
        *count = i + 1;
        if (!pe_map_rva(&pe, table_rva + (uint32_t)i * 12u,
                        &record, &record_available) || record_available < 12) goto done;
        name_va = le32(record);
        compressed = le32(record + 4);
        record_size = le32(record + 8);
        if (name_va < pe.image_base || (compressed != 0 && compressed != 1) ||
            !record_size || record_size > size - offset) goto done;
        name_rva = name_va - pe.image_base;
        if (!pe_map_rva(&pe, name_rva, &name_data, &name_available)) goto done;
        end = (const unsigned char *)memchr(name_data, 0, name_available);
        if (!end || end == name_data) goto done;
        length = (size_t)(end - name_data);
        if (length > 4096) goto done;
        e->name = (char *)allocate(length + 1);
        memcpy(e->name, name_data, length + 1);
        if (strncmp(e->name, path_prefix, strlen(path_prefix))) goto done;
        if (compressed) {
            if (record_size < 4) goto done;
            e->size = le32(data + offset);
            e->stored = record_size - 4;
            e->offset = offset + 4;
            e->method = METHOD_LZARI;
        } else {
            e->size = record_size;
            e->stored = record_size;
            e->offset = offset;
            e->method = METHOD_RAW;
        }
        if (e->size > SIZE_LIMIT - total || (e->size && !e->stored)) goto done;
        total += e->size;
        offset += record_size;
        if (!prepare_entry_path(entries, *count)) goto done;
    }
    if (offset != size) goto done;
    ok = 1;
done:
    if (!ok) {
        fprintf(stderr, "error: %s metadata table or archive is inconsistent\n", format_name);
        free_entries(entries, *count);
        *count = 0;
    } else {
        *result = entries;
    }
    return ok;
}

static int extract_entries(const unsigned char *data, Entry *entries, size_t count, const char *output)
{
    size_t i, total = 0, root_length = strlen(output);
    if (!root_length || path_kind(output) != 0) {
        fprintf(stderr, "error: destination must be a new directory: %s\n", output); return 0;
    }
    /* Validate every compressed payload before making any output directory. */
    for (i = 0; i < count; ++i) {
        Entry *e = &entries[i];
        size_t j;
        e->decoded = (unsigned char *)allocate(e->size);
        if (e->method == METHOD_XOR_9A) {
            for (j = 0; j < e->size; ++j) e->decoded[j] = data[e->offset + j] ^ 0x9a;
        } else if (e->method == METHOD_RAW) {
            memcpy(e->decoded, data + e->offset, e->size);
        } else if (!decode_lzari(data + e->offset, e->stored, e->decoded, e->size)) {
            fprintf(stderr, "error: invalid LZARI payload: %s\n", e->path); return 0;
        }
        total += e->size;
    }
    if (!make_tree(output)) {
        fprintf(stderr, "error: could not create destination: %s\n", output); return 0;
    }
    for (i = 0; i < count; ++i) {
        Entry *e = &entries[i];
        char *path = (char *)allocate(root_length + strlen(e->path) + 2);
        char *slash;
        FILE *file;
        int ok;
        memcpy(path, output, root_length); path[root_length] = '/';
        strcpy(path + root_length + 1, e->path);
        slash = strrchr(path, '/');
        *slash = '\0'; ok = make_tree(path); *slash = '/';
        if (!ok || path_kind(path) != 0 || !(file = open_file(path, 1))) {
            fprintf(stderr, "error: could not create file: %s\n", path); free(path); return 0;
        }
        ok = fwrite(e->decoded, 1, e->size, file) == e->size;
        if (fclose(file)) ok = 0;
        if (!ok) remove_created_file(path);
        free(path);
        if (!ok) { fprintf(stderr, "error: writing %s failed\n", e->path); return 0; }
    }
    printf("Extracted %zu files (%zu bytes) to %s\n", count, total, output);
    return 1;
}

static int run(int argc, char **argv)
{
    const char *archive = NULL, *output = NULL, *metadata_path = NULL;
    unsigned char *data, *metadata = NULL;
    Entry *entries = NULL;
    size_t size = 0, metadata_size = 0, count = 0, i;
    int arg = 1, positional = 0, list = 0, metadata_mode = 0, ok;
    while (arg < argc) {
        if (!strcmp(argv[arg], "--help") || !strcmp(argv[arg], "-h")) {
            printf("Usage: klx_unpack [--list] archive.klx [new-output-directory]\n"
                   "       klx_unpack [--list] --ltp3-exe LTP3.exe data [new-output-directory]\n"
                   "       klx_unpack [--list] --dash-exe Dash.exe Dash.GCR [new-output-directory]\n"
                   "nX/X3 FXLK and external-table LZARI extractor. Limit: 256 MiB.\n");
            return 0;
        } else if (!strcmp(argv[arg], "--list")) {
            list = 1;
            ++arg;
        } else if ((!strcmp(argv[arg], "--ltp3-exe") ||
                    !strcmp(argv[arg], "--dash-exe")) && arg + 1 < argc) {
            if (metadata_path) {
                fprintf(stderr, "error: choose only one metadata executable mode\n");
                return 1;
            }
            metadata_mode = !strcmp(argv[arg], "--dash-exe") ? 2 : 1;
            metadata_path = argv[arg + 1];
            arg += 2;
        } else if (argv[arg][0] == '-') {
            fprintf(stderr, "error: unknown or incomplete option: %s\n", argv[arg]);
            return 1;
        } else {
            if (positional == 0) archive = argv[arg];
            else if (positional == 1) output = argv[arg];
            else {
                fprintf(stderr, "error: too many positional arguments\n");
                return 1;
            }
            ++positional;
            ++arg;
        }
    }
    if (!archive || (list ? output != NULL : output == NULL)) {
        fprintf(stderr, "Usage: klx_unpack [--list] archive.klx [new-output-directory]\n"
                        "       klx_unpack [--list] --ltp3-exe LTP3.exe data [new-output-directory]\n"
                        "       klx_unpack [--list] --dash-exe Dash.exe Dash.GCR [new-output-directory]\n");
        return 1;
    }
    data = read_file(archive, &size);
    if (!data) { fprintf(stderr, "error: could not read archive (limit 256 MiB): %s\n", archive); return 1; }
    if (metadata_path) {
        metadata = read_file(metadata_path, &metadata_size);
        if (!metadata) {
            fprintf(stderr, "error: could not read metadata executable: %s\n", metadata_path);
            free(data);
            return 1;
        }
        if (metadata_mode == 2) {
            ok = parse_external_archive(data, size, metadata, metadata_size,
                                        DASH_TABLE_RVA, DASH_ENTRY_COUNT,
                                        "D:/vrac/", "Dash", &entries, &count);
        } else {
            ok = parse_external_archive(data, size, metadata, metadata_size,
                                        LTP3_TABLE_RVA, LTP3_ENTRY_COUNT,
                                        "D:/Devellop/LTP3-Iinvit/", "LTP3",
                                        &entries, &count);
        }
    } else {
        ok = parse_archive(data, size, &entries, &count);
    }
    if (ok && list) {
        for (i = 0; i < count; ++i) {
            Entry *e = &entries[i];
            printf("%9zu %9u %9u %-7s %s\n", e->offset, (unsigned int)e->stored,
                   (unsigned int)e->size, method_name(e->method), e->path);
        }
        printf("%zu files\n", count);
    } else if (ok) ok = extract_entries(data, entries, count, output);
    free_entries(entries, count); free(metadata); free(data);
    return ok ? 0 : 1;
}

#ifdef _WIN32
int wmain(int argc, wchar_t **wide_argv)
{
    char **argv = (char **)allocate((size_t)argc * sizeof(*argv));
    int i, result;
    for (i = 0; i < argc; ++i) {
        int size = WideCharToMultiByte(CP_UTF8, 0, wide_argv[i], -1, NULL, 0, NULL, NULL);
        if (!size) { fprintf(stderr, "error: invalid command line\n"); exit(1); }
        argv[i] = (char *)allocate((size_t)size);
        WideCharToMultiByte(CP_UTF8, 0, wide_argv[i], -1, argv[i], size, NULL, NULL);
    }
    result = run(argc, argv);
    for (i = 0; i < argc; ++i) free(argv[i]);
    free(argv);
    return result;
}
#else
int main(int argc, char **argv) { return run(argc, argv); }
#endif
