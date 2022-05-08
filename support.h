/**
 * SPDX-License-Identifier: GPL-2.0-or-later
 * 
 * @file support.h
 * @author Stefano Moioli <smxdev4@gmail.com>
 * @brief 
 * @version 0.1
 * @date 2022-05-08
 * 
 * @copyright Copyright (c) 2022
 * 
 */
#ifndef __ARGON_SUPPORT_H
#define __ARGON_SUPPORT_H

#ifdef WIN32
#include <windows.h>
#else
#include <dlfcn.h>
#endif


#ifdef WIN32
#define LIB_OPEN(lib) LoadLibraryA(lib)
#define LIB_CLOSE(handle) FreeLibrary(handle)
#define LIB_GETSYM(handle, sym) (void *)GetProcAddress(handle, sym)
#define LIB_PERROR(out) fprintf(out, "LoadLibraryA failed: 0x%08X\n", GetLastError())
typedef HMODULE libhandle_t;
#else
#define LIB_OPEN(lib) dlopen(lib, RTLD_LAZY)
#define LIB_CLOSE(handle) dlclose(handle)
#define LIB_GETSYM(handle, sym) dlsym(handle, sym)
#define LIB_PERROR(out) fprintf(out, "dlopen() failed: %s\n", dlerror());
typedef void * libhandle_t;
#endif

#endif