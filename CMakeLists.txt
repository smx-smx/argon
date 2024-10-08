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

#add_compile_options(-Wall)
if(WIN32)
	add_compile_options(-Wl,--export-all-symbols)
endif()

if(CMAKE_BUILD_TYPE MATCHES Debug)
	separate_arguments(BINUTILS_CFLAGS NATIVE_COMMAND "${CMAKE_C_FLAGS_DEBUG}")
	list(APPEND BINUTILS_CFLAGS -ggdb3)
elseif(CMAKE_BUILD_TYPE MATCHES Release)
	separate_arguments(BINUTILS_CFLAGS NATIVE_COMMAND "${CMAKE_C_FLAGS_RELEASE}")
endif()

list(APPEND BINUTILS_CFLAGS -fPIC)

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
		COMMAND ${CMAKE_C_COMPILER} -dumpmachine
		OUTPUT_VARIABLE HOST
		OUTPUT_STRIP_TRAILING_WHITESPACE
	)
endif()
if(NOT DEFINED TARGET)
	set(TARGET "x86_64-unknown-linux")
endif()

set(AUTOTOOLS_ENV "")
list(APPEND AUTOTOOLS_ENV
	REAL_CC="${CMAKE_C_COMPILER}"
	CC="${CMAKE_SOURCE_DIR}/cc_wrap"
	CFLAGS="${BINUTILS_CFLAGS}"
	MAKEINFO=true
)

# make clean will delete the bindir. recreate it
add_custom_command(
	OUTPUT ${binutils_BINARY_DIR}
	COMMAND ${CMAKE_COMMAND} -E make_directory ${binutils_BINARY_DIR}
)
add_custom_target(mkdir_binutils
	DEPENDS ${binutils_BINARY_DIR}
)

add_custom_command(
	OUTPUT ${binutils_BINARY_DIR}/config.status
	WORKING_DIRECTORY ${binutils_BINARY_DIR}
	COMMAND ${CMAKE_COMMAND} -E env 
		${AUTOTOOLS_ENV}
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
set_target_properties(configure_binutils
	PROPERTIES
	ADDITIONAL_CLEAN_FILES ${binutils_BINARY_DIR}
)
add_dependencies(configure_binutils mkdir_binutils)

## build gas objects
add_custom_target(build_gas
	WORKING_DIRECTORY ${binutils_BINARY_DIR}
	COMMAND ${CMAKE_COMMAND} -E env
	${AUTOTOOLS_ENV}
	make -j${NPROC} all-gas
	COMMAND make install-gas
	COMMENT "make install-gas"
)
add_dependencies(build_gas configure_binutils)

## build opcodes objects and libopcodes
add_custom_target(build_opcodes
	WORKING_DIRECTORY ${binutils_BINARY_DIR}
	COMMAND ${CMAKE_COMMAND} -E env
	${AUTOTOOLS_ENV}
	make -j${NPROC} all-opcodes
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

# using SHARED implies position-independent code
add_library(binutils_glue SHARED
	glue.c
	wrappers.cpp
	dynapi.c
)
target_include_directories(binutils_glue PRIVATE
	${binutils_BINARY_DIR}/bfd
	${binutils_BINARY_DIR}/gas
	${binutils_SOURCE_DIR}/include
	${binutils_SOURCE_DIR}
	${binutils_SOURCE_DIR}/gas
	${binutils_SOURCE_DIR}/gas/config
)
set_target_properties(binutils_glue
	PROPERTIES
		# don't actually create a .a/.so (we will use the .o files later)
		RULE_LAUNCH_LINK "${CMAKE_COMMAND} -E true"
)
add_dependencies(binutils_glue build_gas)

set(OPCODES_OBJECTS opcodes/*.o)

if("${TARGET}" MATCHES "avr-.*"
OR "${TARGET}" MATCHES "sh4-.*")
	set(OPCODES_OBJECTS "")
endif()

set(LIBGAS_LDFLAGS "")
list(APPEND LIBGAS_LDFLAGS -lstdc++)
if(WIN32)
	# bigger binary, but self contained (libstdc++ and libgcc)
	list(APPEND LIBGAS_LDFLAGS -static)
endif()

## build libgas shared library
add_custom_target(build_gas_shared
	WORKING_DIRECTORY ${binutils_BINARY_DIR}
	COMMAND_EXPAND_LISTS
	COMMAND ${CMAKE_C_COMPILER}
		${BINUTILS_CFLAGS}
		-shared
		# GC malloc hooks
		-Wl,--wrap=malloc
		-Wl,--wrap=free
		-Wl,--wrap=realloc
		-Wl,--wrap=calloc
		# TC pseudo ops
		-Wl,--wrap=pop_insert
		# fake ELF hooks
		-Wl,--wrap=bfd_elf_obj_attr_size
		-Wl,--wrap=bfd_set_symtab
		-Wl,--wrap=bfd_elf_get_obj_attr_int
		-Wl,--wrap=_bfd_elf_set_section_contents
		# Output hooks
		-Wl,--wrap=_bfd_real_fopen
		-Wl,--wrap=fclose
		# add glue and wrappers
		$<TARGET_OBJECTS:binutils_glue>
		gas/*.o
		gas/config/*.o
		${OPCODES_OBJECTS}
		bfd/*.o
		libiberty/*.o
		zlib/*.o
		${LIBGAS_LDFLAGS}
		-o gas/${GAS_SHARED_LIB_NAME}
)
add_dependencies(build_gas_shared build_gas)
add_dependencies(build_gas_shared binutils_glue)

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

add_executable(rapl_test rapl_test.cpp)
if(UNIX AND NOT CYGWIN)
	target_link_libraries(rapl_test PRIVATE dl)
endif()
if(WIN32)
	# only required for the clock_gettime perf test
	target_link_libraries(rapl_test PRIVATE pthread)
	target_compile_options(rapl_test PRIVATE -static)
endif()
add_dependencies(rapl_test copy_libgas)