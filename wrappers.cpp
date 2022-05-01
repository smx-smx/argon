/**
 * SPDX-License-Identifier: GPL-2.0-or-later
 * 
 * @file wrappers.cpp
 * @author Stefano Moioli (smxdev4@gmail.comcom)
 * @brief 
 * @version 0.1
 * @date 2022-05-01
 * 
 * @copyright Copyright (c) 2022
 * 
 */
#include <cstdio>
#include <cstdint>
#include <algorithm>

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
	return info;
}
#else
#include <unordered_set>
static std::unordered_set<void *> g_allocations;
#endif


extern "C" {

#if 1
uintptr_t __wrap_bfd_elf_obj_attr_size (void *abfd){
	return 0;
}
bool __wrap_bfd_set_symtab (void *abfd, void **location, unsigned int symcount){
	return true;
}
#endif


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
#ifdef DEBUG
	g_allocations[ptr] = make_info(size);
#else
	g_allocations.insert(ptr);
#endif
	
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
#ifdef DEBUG
	g_allocations[ptr] = make_info(size);
#else
	g_allocations.insert(ptr);
#endif
	
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
#ifdef DEBUG
	g_allocations[ptr] = make_info(size);
#else
	g_allocations.insert(ptr);
#endif
	return ptr;
}

void __wrap_free(void *ptr){
	g_allocations.erase(ptr);
	__real_free(ptr);
}

/**
 * @brief Frees all the memory allocations that haven't been freed 
 */
void malloc_gc(){
	for(auto const& item : g_allocations){
	#ifdef DEBUG
		void *ptr = item.first;
		struct alloc_info caller = item.second;
		printf(">> gc free %p (%p -> %p -> %p)\n", ptr,
			caller.bt[0], caller.bt[1], caller.bt[2]);
	#else
		void *ptr = item;
	#endif
		__real_free(ptr);
	}
	g_allocations.clear();
}

}