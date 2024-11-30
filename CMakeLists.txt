cmake_minimum_required(VERSION 3.12)
project(RouterEx)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_GNU_SOURCE")
set(CMAKE_BUILD_TYPE Debug)

# set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static")

add_executable(RouterEx router.c)

# set(EVENT__LIBRARY_TYPE STATIC CACHE STRING "Build libevent as a static library")
# set(OPENSSL_USE_STATIC_LIBS TRUE CACHE STRING "Link OpenSSL statically")

add_subdirectory(lib/libevent)
add_subdirectory(lib/libpatricia)
target_link_libraries(RouterEx PRIVATE 
    event 
    event_core 
    event_extra 
    cccommon
)
target_include_directories(RouterEx PRIVATE
    ${CMAKE_SOURCE_DIR}/lib/libevent/include
    ${CMAKE_SOURCE_DIR}/lib/libpatricia/libpatricia
)

add_dependencies(RouterEx cccommon)