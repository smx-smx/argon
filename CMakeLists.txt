##
# Author: Stefano Moioli <smxdev4@gmail.com>
##
cmake_minimum_required(VERSION 3.20)

project(binutils C CXX)

include(FetchContent)
include(ProcessorCount)

ProcessorCount(NPROC)

Set(FETCHCONTENT_QUIET FALSE)
FetchContent_Declare(
	binutils
	GIT_REPOSITORY https://sourceware.org/git/binutils-gdb.git
	GIT_TAG binutils-2_38
	GIT_SHALLOW TRUE
	GIT_PROGRESS TRUE
)
FetchContent_MakeAvailable(binutils)

if(NOT CMAKE_BUILD_TYPE)
	set(CMAKE_BUILD_TYPE Debug)
endif()


set(BINUTILS_CFLAGS -fPIC)

if(CMAKE_BUILD_TYPE MATCHES Debug)
	list(APPEND BINUTILS_CFLAGS -g -ggdb3)
endif()

macro(static_lib_name name var)
	set(${var} ${CMAKE_STATIC_LIBRARY_PREFIX}${name}${CMAKE_STATIC_LIBRARY_SUFFIX})
endmacro()
macro(shared_lib_name name var)
	set(${var} ${CMAKE_SHARED_LIBRARY_PREFIX}${name}${CMAKE_SHARED_LIBRARY_SUFFIX})
endmacro()

static_lib_name(gas GAS_STATIC_LIB_NAME)
shared_lib_name(gas GAS_SHARED_LIB_NAME)


if(NOT DEFINED HOST)
	execute_process(
		COMMAND cc -dumpmachine
		OUTPUT_VARIABLE HOST
		OUTPUT_STRIP_TRAILING_WHITESPACE
	)
endif()
if(NOT DEFINED TARGET)
	set(TARGET "x86_64-unknown-linux")
endif()

add_custom_command(
	OUTPUT ${binutils_BINARY_DIR}/config.status
	WORKING_DIRECTORY ${binutils_BINARY_DIR}
	COMMAND ${CMAKE_COMMAND} -E env CFLAGS="${BINUTILS_CFLAGS}"
		${binutils_SOURCE_DIR}/configure 
		--disable-nls
		--prefix=${binutils_BINARY_DIR}
		--host=${HOST}
		--target=${TARGET}
		--disable-werror
)

## run configure script
add_custom_target(configure_binutils
	DEPENDS ${binutils_BINARY_DIR}/config.status
	COMMENT "configuring binutils"
)

## build gas objects
add_custom_target(build_gas
	WORKING_DIRECTORY ${binutils_BINARY_DIR}
	COMMAND ${CMAKE_COMMAND} -E env MAKEINFO=true make -j${NPROC} all-gas
	COMMAND make install-gas
	COMMENT "make install-gas"
)
add_dependencies(build_gas configure_binutils)

## build opcodes objects and libopcodes
add_custom_target(build_opcodes
	WORKING_DIRECTORY ${binutils_BINARY_DIR}
	COMMAND ${CMAKE_COMMAND} -E env MAKEINFO=true make -j${NPROC} all-opcodes
	COMMAND make install-opcodes
	COMMENT "make install-opcodes"
)
add_dependencies(build_opcodes configure_binutils)

## (not verified) create libgas.a static library
add_custom_target(build_gas_static
	WORKING_DIRECTORY ${binutils_BINARY_DIR}
	COMMAND ${CMAKE_AR} rcs gas/${GAS_STATIC_LIB_NAME}
		gas/*.o 
		gas/config/*.o 
		opcodes/*.o 
		bfd/*.o
	COMMENT "building static libgas"
)
add_dependencies(build_gas_static build_gas)

## build malloc wrappers
add_custom_command(
	OUTPUT ${binutils_BINARY_DIR}/wrappers.o
	DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/wrappers.cpp 
	COMMAND ${CMAKE_CXX_COMPILER} ${BINUTILS_CFLAGS}
		-c ${CMAKE_CURRENT_SOURCE_DIR}/wrappers.cpp
		-o ${binutils_BINARY_DIR}/wrappers.o
)
add_custom_target(build_wrappers
	DEPENDS ${binutils_BINARY_DIR}/wrappers.o
	COMMENT "building malloc wrappers"
)
add_dependencies(build_wrappers build_gas)

## build libgas shared library
add_custom_target(build_gas_shared
	WORKING_DIRECTORY ${binutils_BINARY_DIR}
	COMMAND ${CMAKE_C_COMPILER} ${CMAKE_C_FLAGS}
		-shared
		-Wl,--wrap=malloc
		-Wl,--wrap=free
		-Wl,--wrap=realloc
		-Wl,--wrap=calloc
		-Wl,--wrap=bfd_elf_obj_attr_size
		-Wl,--wrap=bfd_set_symtab
		wrappers.o
		gas/*.o
		gas/config/*.o
		opcodes/*.o
		bfd/*.o
		libiberty/*.o
		zlib/*.o
		-lstdc++
		-o gas/${GAS_SHARED_LIB_NAME}
)
add_dependencies(build_gas_shared build_gas)
add_dependencies(build_gas_shared build_wrappers)

add_library(libgas SHARED IMPORTED)
set_property(
	TARGET libgas
	PROPERTY
	IMPORTED_LOCATION ${binutils_BINARY_DIR}/gas/${GAS_SHARED_LIB_NAME}
)

add_custom_command(
	OUTPUT ${CMAKE_BINARY_DIR}/${GAS_SHARED_LIB_NAME}
	DEPENDS ${binutils_BINARY_DIR}/gas/${GAS_SHARED_LIB_NAME}
	COMMAND ${CMAKE_COMMAND} -E copy ${binutils_BINARY_DIR}/gas/${GAS_SHARED_LIB_NAME} ${CMAKE_BINARY_DIR}/${GAS_SHARED_LIB_NAME}
)
add_custom_target(copy_libgas
	DEPENDS ${CMAKE_BINARY_DIR}/${GAS_SHARED_LIB_NAME}
	COMMENT "copying ${GAS_SHARED_LIB_NAME}"
)
add_dependencies(copy_libgas build_gas_shared)

add_executable(rapl_test rapl_test.c)
target_link_libraries(rapl_test PRIVATE dl)
add_dependencies(rapl_test copy_libgas)