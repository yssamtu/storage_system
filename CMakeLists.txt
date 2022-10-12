# MIT License
#Copyright (c) 2021-2022
#Authors:  Animesh Trivedi
#This code is part of the Storage System Course at VU Amsterdam
#Permission is hereby granted, free of charge, to any person obtaining a copy
#of this software and associated documentation files (the "Software"), to deal
#in the Software without restriction, including without limitation the rights
#to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
#copies of the Software, and to permit persons to whom the Software is
#furnished to do so, subject to the following conditions:
#The above copyright notice and this permission notice shall be included in all
#copies or substantial portions of the Software.
#THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
#OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
#SOFTWARE.

cmake_minimum_required(VERSION 3.16)
project(stosys-project VERSION 1.0.1 DESCRIPTION "StoSys project code for Storage Systems class at VU Amsterdam. (c) Animesh Trivedi.")
message(STATUS "Building using CMake version: ${CMAKE_VERSION}")

set(CMAKE_CXX_STANDARD 14)
#add_compile_options("-std=c++17")
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_PREFIX_PATH "/home/$ENV{USER}/local/")
set(CMAKE_LIBRARY_PATH "/home/$ENV{USER}/local/lib/")
set(CMAKE_INSTALL_PREFIX "/home/$ENV{USER}/local/")

# Project configuration specific parameters
set(STOSYS_M45 OFF)
set(STOSYS_CMAKE_DEBUG OFF)
set(STOSYS_ASAN ON)

find_package(PkgConfig REQUIRED)
if(NOT PKG_CONFIG_FOUND)
    message(FATAL_ERROR "pkg-config command not found!" )
endif()

# the name of these packages come from the .pc files, such as
# see cat ~/local/lib/pkgconfig/libnvme.pc
pkg_search_module(NVME REQUIRED libnvme)

set(PROJECT_SOURCE_DIR ${CMAKE_SOURCE_DIR}/src)
set(CMAKE_BINARY_DIR ${CMAKE_SOURCE_DIR}/bin)
set(CMAKE_LIB_DIR ${CMAKE_SOURCE_DIR}/lib)
set(EXECUTABLE_OUTPUT_PATH ${CMAKE_BINARY_DIR})
set(LIBRARY_OUTPUT_PATH ${CMAKE_LIB_DIR})

set(CMAKE_BUILD_TYPE Debug) # or debug if you need to use gdb on it.

# Some how g++ has better performance than clang++. Of course I don't know all flags for clang++.
set(CMAKE_CXX_COMPILER g++) # or clang++
#set(CMAKE_CXX_COMPILER clang++) # or clang++
message("compiler is ${CMAKE_CXX_COMPILER_ID}   and name is ${CMAKE_CXX_COMPILER}")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -O0  -ggdb -Wl,--no-as-needed -Wall -Wextra")
# optimization flags
#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O2 -Ofast -ffast-math -funroll-loops -march=native") # get crazy here
# debug flags, needs a bit of customization
# https://stackoverflow.com/questions/10046114/in-cmake-how-can-i-test-if-the-compiler-is-clang
# FIXME: I really do not know  man, I am out of ideas at this point...every single time, agh :(
if (CMAKE_CXX_COMPILER STREQUAL "clang++")
    # using Clang
    message("[info] compiler is clang")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}  -frtti")
elseif (CMAKE_CXX_COMPILER STREQUAL "g++")
    # using GCC
    message("[info] compiler is gcc/g++")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}  --rtti")
elseif (CMAKE_CXX_COMPILER_ID STREQUAL "Intel")
    # using Intel C++
    message("[info] Intel compiler? not sure which flags to pick up")
elseif (CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
    # using Visual Studio C++
    message("[info] Whoaa....let me stop you right here")
endif()

if (STOSYS_ASAN)
    message("[info] ASAN is on, adding additional ASAN fields to the compiler ")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}  -fsanitize=address -fsanitize=undefined -fno-sanitize-recover=all -fsanitize=float-divide-by-zero -fsanitize=float-cast-overflow -fno-sanitize=null -fno-sanitize=alignment")
endif()

include(GNUInstallDirs)
include_directories (${NVME_INCLUDE_DIRS})
link_directories (${NVME_LIBRARY_DIRS})
add_executable(m1 src/m1/m1.cpp src/m1/device.h src/m1/device.cpp src/common/nvmeprint.cpp src/common/nvmeprint.h src/common/utils.cpp src/common/utils.h src/common/stosys_debug.h)
add_definitions (${NVME_CFLAGS})
target_link_libraries(m1 ${NVME_LIBRARIES} pthread)

add_library(stosys SHARED src/m23-ftl/zns_device.cpp src/m23-ftl/zns_device.h src/common/nvmeprint.cpp src/common/nvmeprint.h src/common/utils.cpp src/common/utils.h src/common/stosys_debug.h)
target_link_libraries(stosys ${NVME_LIBRARIES})
set_target_properties(stosys PROPERTIES VERSION ${PROJECT_VERSION})
set_target_properties(stosys PROPERTIES SOVERSION 1)

# There should not be any need for any public headers, I first prototypes it with public headers, but it is not needed
# if we do further decoupled development it might come in handy, but lets not make our lives painful as it is
#set(STOSYS_PUBLIC_HEADERS
#        ${PROJECT_SOURCE_DIR}/common/stosys_debug.h
#        ${PROJECT_SOURCE_DIR}/m23-ftl/ZNSDevice.h
#        ${PROJECT_SOURCE_DIR}/common/utils.h
#        )
set_target_properties(stosys PROPERTIES PUBLIC_HEADER "${STOSYS_PUBLIC_HEADERS}")
include(GNUInstallDirs)
install(TARGETS stosys
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/stosys/)

# library is done. Now link it with all following milestones 2, 3, 4 and 5
add_executable(m2 src/m23-ftl/m2.cpp)
add_definitions (${NVME_CFLAGS})
target_link_libraries(m2 ${NVME_LIBRARIES} pthread stosys)

add_executable(m3 src/m23-ftl/m3.cpp)
add_definitions (${NVME_CFLAGS})
target_link_libraries(m3 ${NVME_LIBRARIES} pthread stosys)

# starting here, we need more setup for RocksDB
if(STOSYS_M45)
    pkg_search_module(ROCKSDB REQUIRED IMPORTED_TARGET rocksdb)
    # these are not exported from ROCKSDB - hence - they need to looked up by us
    pkg_search_module(SNAPPY REQUIRED IMPORTED_TARGET snappy)
    pkg_search_module(ZSTD REQUIRED IMPORTED_TARGET libzstd)
    pkg_search_module(LZ4 REQUIRED IMPORTED_TARGET liblz4)
    # TODO: I have no idea how to look up this package, life sometimes is just pain and misery - this does not have a .pc file
    #pkg_search_module(BZip2 REQUIRED IMPORTED_TARGET bzip2)
    find_package(BZip2)

    add_executable(m45 src/m45-rocksdb/m45_main.cc src/m45-rocksdb/rocks_s2fs.cc src/m45-rocksdb/S2FileSystem.cc src/m45-rocksdb/S2FileSystem.h src/m45-rocksdb/DummyFSForward.cc src/m45-rocksdb/DummyFSForward.h)
    # see all the defined variables here: https://cmake.org/cmake/help/latest/module/FindPkgConfig.html
    add_definitions (${NVME_CFLAGS} ${ROCKSDB_CFLAGS}  ${ROCKSDB_STATIC_CFLAGS} ${ROCKSDB_CFLAGS_OTHER})
    target_link_libraries(m45 pthread stosys ${ROCKSDB_STATIC_LIBRARIES} ${SNAPPY_LIBRARIES} ${ZSTD_LIBRARIES} ${LZ4_LIBRARIES} ${BZIP2_LIBRARIES})
    # if we are not going to install the headers then we need to tell where they are
    target_include_directories(m45 PRIVATE ./src/m23-ftl/ ./src/common/)
else()
    message("[info] not compiling the m4/m5, that needs rocksdb integration, and install the stosys library")
endif()

# Life saver script from https://stackoverflow.com/questions/9298278/cmake-print-out-all-accessible-variables-in-a-script/9328525#9328525
if(STOSYS_CMAKE_DEBUG)
    get_cmake_property(_variableNames VARIABLES)
    list (SORT _variableNames)
    foreach (_variableName ${_variableNames})
           message(STATUS "${_variableName}=${${_variableName}}")
    endforeach()
endif()
