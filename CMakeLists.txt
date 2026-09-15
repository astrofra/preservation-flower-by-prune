cmake_minimum_required(VERSION 3.15)
project(flower_preservation LANGUAGES C)

add_executable(klx_unpack klx_unpack.c)
set_target_properties(klx_unpack PROPERTIES
    C_STANDARD 99
    C_STANDARD_REQUIRED YES
    C_EXTENSIONS NO
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/bin$<0:>"
    MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
)

if(MSVC)
    target_compile_options(klx_unpack PRIVATE /W4 /WX)
else()
    target_compile_options(klx_unpack PRIVATE -Wall -Wextra -Werror)
    if(MINGW)
        target_link_options(klx_unpack PRIVATE -municode)
    endif()
endif()

include(CTest)
if(BUILD_TESTING)
    find_package(Python3 COMPONENTS Interpreter QUIET)
    if(Python3_Interpreter_FOUND)
        add_test(NAME flower_assets COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_CURRENT_SOURCE_DIR}/tests/validate_assets.py" "$<TARGET_FILE:klx_unpack>")
    endif()
endif()
