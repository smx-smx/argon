/**
 * SPDX-License-Identifier: GPL-2.0-or-later
 * 
 * @file wrappers.cpp
 * @author Stefano Moioli (smxdev4@gmail.comcom)
 * @brief GAS internal hooks
 * @version 0.1
 * @date 2022-05-01
 * 
 * @copyright Copyright (c) 2022
 * 
 */
#include "config.h"
#include "bfd.h"
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <algorithm>

//#define DEBUG
#ifdef DEBUG
#include <unordered_map>
struct alloc_info {
	std::vector<void *> bt;
	size_t size;
};
static std::unordered_map<void *, alloc_info> g_allocations;

static inline __attribute__((always_inline))
struct alloc_info make_info(size_t size){
	struct alloc_info info;
	info.size = size;
	info.bt.push_back(__builtin_return_address(0));
	info.bt.push_back(__builtin_return_address(1));
	info.bt.push_back(__builtin_return_address(2));
	info.bt.push_back(__builtin_return_address(3));
	info.bt.push_back(__builtin_return_address(4));
	return info;
}
#else
#include <unordered_set>
static std::unordered_set<void *> g_allocations;
#endif

static std::unordered_set<void *> g_ignores;
static bool g_is_tracking = true;

extern "C" {
static uint8_t *bfd_data = nullptr;
static size_t bfd_data_size = 0;
static size_t bfd_data_count = 0;

/**
 * these hooks are needed to avoid a crash
 * since we are working on an uninitialized ELF file 
 */
uintptr_t __wrap_bfd_elf_obj_attr_size (void *abfd){
	return 0;
}
bool __wrap_bfd_set_symtab (void *abfd, void **location, unsigned int symcount){
	return true;
}

int __wrap_bfd_elf_get_obj_attr_int (void *abfd, int vendor, unsigned int tag){
	return 0;
}

static void *tc_pseudo_table;

void __wrap_pop_insert (const void *table){
	::tc_pseudo_table = const_cast<void *>(table);
}

void *argon_tc_pseudo_ops(){
	return ::tc_pseudo_table;
}

/**
 * @brief Hook for the implementation of "set_section_contents"
 * "elf" because we're targeting the elf-linux backend for now
 **/
bool __wrap__bfd_elf_set_section_contents (
	void *abfd, asection *section,
	const void *location,
	uintptr_t offset,
	uintptr_t count
){
	// skip non-code sections
	if(strcmp(section->name, ".text") != 0){
		return true;
	}

	off_t write_begin = bfd_data_count + offset;
	if(write_begin >= bfd_data_size) return false;

	off_t write_end = write_begin + count;
	if(write_end >= bfd_data_size){
		count -= (write_end - bfd_data_size);
	}
	std::memcpy(&::bfd_data[write_begin], location, count);
	::bfd_data_count += count;
	return true;
}

extern void *__real_malloc(size_t size);
extern void __real_free(void *ptr);
extern void *__real_calloc(size_t nmemb, size_t size);
extern void *__real_realloc(void *ptr, size_t size);

void *__wrap_malloc(size_t size);
void __wrap_free(void *ptr);
void *__wrap_calloc(size_t nmemb, size_t size);
void *__wrap_realloc(void *ptr, size_t size);

/**
 * @brief Wrapper of realloc that stores succesful re-allocations
 * 
 * @param ptr 
 * @param size 
 * @return void* 
 */
void *__wrap_realloc(void *ptr, size_t size){
	g_allocations.erase(ptr);
	ptr = __real_realloc(ptr, size);
	if(ptr == nullptr){
		return nullptr;
	}
	if(::g_is_tracking){	
#ifdef DEBUG
		g_allocations[ptr] = make_info(size);
#else
		g_allocations.insert(ptr);
#endif
	}
	
	return ptr;
}

/**
 * @brief Wrapper of calloc that stores succesful allocations
 * 
 * @param nmemb 
 * @param size 
 * @return void* 
 */
void *__wrap_calloc(size_t nmemb, size_t size){
	void *ptr = __real_calloc(nmemb, size);
	if(ptr == nullptr){
		return nullptr;
	}

	if(::g_is_tracking){
#ifdef DEBUG
		g_allocations[ptr] = make_info(size);
#else
		g_allocations.insert(ptr);
#endif
	}
	
	return ptr;
}

/**
 * @brief Wrapper of malloc that stores succesful allocations
 * 
 * @param size 
 * @return void* 
 */
void *__wrap_malloc(size_t size){
	void *ptr = __real_malloc(size);
	if(ptr == nullptr){
		return nullptr;
	}

	if(::g_is_tracking){
#ifdef DEBUG
		g_allocations[ptr] = make_info(size);
#else
		g_allocations.insert(ptr);
#endif
	}
	return ptr;
}

void __wrap_free(void *ptr){
	if(g_allocations.find(ptr) != g_allocations.end()){
		g_allocations.erase(ptr);
		__real_free(ptr);
	}
}

void argon_gcl_enable(int enable){
	::g_is_tracking = enable;
}

void argon_gcl_skip(void *ptr){
	::g_ignores.insert(ptr);
}

void argon_gcl_clear(){
	::g_ignores.clear();
}

/**
 * @brief Frees all the memory allocations that haven't been freed 
 */
void argon_malloc_gc(){
	auto ign_end = g_ignores.end();

	for(auto const& item : g_allocations){
	#ifdef DEBUG
		void *ptr = item.first;
		struct alloc_info caller = item.second;
		printf(">> gc free %p (%p -> %p -> %p -> %p -> %p)\n", ptr,
			caller.bt[0], caller.bt[1], caller.bt[2],
			caller.bt[3], caller.bt[4]);
	#else
		void *ptr = item;
	#endif
		//if(::g_ignores.find(ptr) == ign_end){
			__real_free(ptr);
		//}
	}
	g_allocations.clear();
}

void *argon_bfd_data_alloc(size_t size){
	// allocate through the real malloc
	::bfd_data = static_cast<uint8_t *>(__real_malloc(size));
	if(bfd_data != nullptr){
		::bfd_data_size = size;
	}
	::bfd_data_count = 0;
	return ::bfd_data;
}

size_t argon_bfd_data_written(){
	return ::bfd_data_count;
}

void argon_fseek(long offset, int whence){
	size_t p = ::bfd_data_count;
	switch(whence){
		case SEEK_SET:
			p = offset;
			break;
		case SEEK_END:
			p += ::bfd_data_size + offset;
			break;
		case SEEK_CUR:
			p += offset;
			break;
	}
	::bfd_data_count = p;
}

#define FAKE_OUTPUT_HANDLE (FILE *)(-2)

extern int __real_fclose(FILE *stream);
int __wrap_fclose(FILE *stream){
	if(stream == FAKE_OUTPUT_HANDLE){
		return 0;
	}
	return __real_fclose(stream);
}

FILE *__wrap__bfd_real_fopen (const char *filename, const char *modes){
	(void)filename;
	(void)modes;
	return FAKE_OUTPUT_HANDLE;
}
}