/**
 * SPDX-License-Identifier: GPL-2.0-or-later
 * 
 * @file argon_api.h
 * @author Stefano Moioli <smxdev4@gmail.com>
 * @brief 
 * @version 0.1
 * @date 2022-05-08
 * 
 * @copyright Copyright (c) 2022
 * 
 */
#ifndef __ARGON_API_H
#define __ARGON_API_H

void argon_reset_gas(unsigned flags);
int argon_set_option(const char *optname, const char *value);
int argon_call_pseudo(const char *op, char *args);
void argon_gcpool_set(int pool_selector);

/** wrappers for the real allocator **/
void *argon_malloc(size_t sz);
void argon_free(void *ptr);
char *argon_strdup(const char *str);

void argon_malloc_gc(int pool_selector);

void *argon_bfd_data_alloc(size_t size);

#endif