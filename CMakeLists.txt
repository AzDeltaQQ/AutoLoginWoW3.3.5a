cmake_minimum_required(VERSION 3.10)
project(WoWAutoLogin)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Set build type to Release for better performance
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# Force 32-bit compilation for WoW compatibility
# set(CMAKE_GENERATOR_PLATFORM Win32)  # Not needed when using explicit 32-bit compilers

# Add executable
add_executable(WoWAutoLogin main.cpp config.h)

# Set compiler flags
if(MSVC)
    # Visual Studio specific flags - force 32-bit
    target_compile_options(WoWAutoLogin PRIVATE /O2 /DNDEBUG)
    # Disable warnings about unsafe functions
    target_compile_definitions(WoWAutoLogin PRIVATE _CRT_SECURE_NO_WARNINGS)
else()
    # GCC/Clang flags - force 32-bit
    target_compile_options(WoWAutoLogin PRIVATE -O2 -DNDEBUG -m32)
    target_link_options(WoWAutoLogin PRIVATE -m32)
endif()

# Link Windows libraries
target_link_libraries(WoWAutoLogin kernel32 user32 advapi32)

# Set output directory
set_target_properties(WoWAutoLogin PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)

# Copy executable to current directory after build
add_custom_command(TARGET WoWAutoLogin POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:WoWAutoLogin> ${CMAKE_SOURCE_DIR}/WoWAutoLogin.exe
) 