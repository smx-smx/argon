/**
 * SPDX-License-Identifier: GPL-2.0-or-later
 * 
 * @file libgas.c
 * @author Stefano Moioli <smxdev4@gmail.com>
 * @brief this example implements a GAS assembler RAPL - Read Assemble Print Loop
 * @version 0.1
 * @date 2022-04-28
 * 
 * @copyright Copyright (c) Stefano Moioli 2022
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>

#ifdef WIN32
#include <windows.h>
#else
#include <dlfcn.h>
#endif

#include "argon.h"

#define UNUSED(x) ((void)(x))

#ifdef WIN32
static HMODULE gas;
#else
static void *gas;
#endif

#ifdef __cplusplus
template<typename T>
static void resolveSymbol(const char *sym, T& outSym){
	void *psym = NULL;
#ifdef WIN32
	psym = (void *)GetProcAddress(gas, sym);
#else
	psym = dlsym(gas, sym);
#endif

	outSym = reinterpret_cast<T>(psym);
}
#else
static void *resolveSymbol(const char *sym){
#ifdef WIN32
	return (void *)GetProcAddress(gas, sym);
#else
	return dlsym(gas, sym);
#endif
}
#endif

#define BINUTILS_IMPORT_DECL
#include "binutils_imports.h"
#undef BINUTILS_IMPORT_DECL

#if 1
#define DPRINTF(fmt, ...)
#define DPUTS(str)
#else
#define DPRINTF(fmt, ...) printf(fmt, __VA_ARGS__)
#define DPUTS(str) puts(str)
#endif

#ifdef WIN32
int launchDebugger() {
	char systemDir[MAX_PATH + 1] = {0};
	UINT nChars = GetSystemDirectoryA(&systemDir[0], sizeof(systemDir));
	if (nChars == 0){
		return FALSE;
	}

	DWORD pid = GetCurrentProcessId();

	char cmdline[256];
	sprintf(cmdline, "%s\\vsjitdebugger.exe -p %u", systemDir, pid);

	STARTUPINFOA si;
	memset(&si, 0x00, sizeof(si));
	si.cb = sizeof(si);

	PROCESS_INFORMATION pi;
	memset(&pi, 0x00, sizeof(pi));

	if (!CreateProcessA(
		NULL,
		&cmdline[0],
		NULL, NULL,
		FALSE, 0, NULL, NULL,
		&si, &pi
	)) {
		return FALSE;
	}

	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);

	while (!IsDebuggerPresent())
		Sleep(100);

	DebugBreak();
	return TRUE;
}
#endif

void breakpoint_me(){
	puts("");
}

#include <time.h>
#include <unistd.h>
#include <pthread.h>

// call this function to start a nanosecond-resolution timer
static inline struct timespec timer_start(){
    struct timespec start_time;
    clock_gettime(CLOCK_MONOTONIC, &start_time);
    return start_time;
}

// call this function to end a timer, returning nanoseconds elapsed as a long
static inline long timer_end(struct timespec start_time){
    struct timespec end_time;
    clock_gettime(CLOCK_MONOTONIC, &end_time);
    long diffInNanos = (end_time.tv_sec - start_time.tv_sec) * (long)1e9 + (end_time.tv_nsec - start_time.tv_nsec);
    return diffInNanos;
}

void* bench(void *arg){
	return NULL;
}

void perf(){
	double millis = 0;
	long opers = 0;
	for(;;++opers){
		struct timespec ts = timer_start();
		{
			argon_init_gas(0, ARGON_KEEP_BUFFER | ARGON_SKIP_INIT);
			argon_fseek(0, SEEK_SET);
			argon_assemble("jmp .");
		}
		long diff = timer_end(ts);
		double diff_millis = diff / 1e6;
		millis += diff_millis;
		if(millis >= 1000){
			fprintf(stderr, "%ld ops/s\n", opers);
			millis = 0;
			opers = 0;
		}
	}
}

int main(int argc, char *argv[]){
	UNUSED(argc);
	UNUSED(argv);

	//launchDebugger();

	//setvbuf(stdout, NULL, _IONBF, 0);
	//setvbuf(stderr, NULL, _IONBF, 0);

	//#define LIB_NAME "gas-x86_64-unknown-linux"
	#define LIB_NAME argv[1]

#ifdef WIN32
	gas = LoadLibraryA(LIB_NAME);
#else
	gas = dlopen(LIB_NAME, RTLD_NOW);
#endif

	if(gas == NULL){
		fprintf(stderr, "LoadLibraryA failed\n");
		fprintf(stderr, "%s\n", dlerror());
		return 1;
	}
	#include "binutils_imports.h"

	uint8_t *mem = argon_init_gas(1024 * 1024,
		ARGON_RESET_FULL | ARGON_FAST_INIT);

#if 0
	char buffer[128] = {0};
	while(!feof(stdin)){
		buffer[0] = '\0';
		argon_init_gas(0, ARGON_KEEP_BUFFER | ARGON_SKIP_INIT);
		argon_fseek(0, SEEK_SET);

		fgets(buffer, sizeof(buffer), stdin);
		char *p = strrchr(buffer, '\n');
		if(p) *p = '\0';

		if(strlen(buffer) < 1){
			continue;
		}
		if(!strcmp(buffer, ".quit")){
			break;
		}
		printf("<= %s\n", buffer);
		argon_assemble(buffer);
		size_t written = argon_bfd_data_written();
		for(size_t i=0; i<written; i++){
			printf("%02hhx ", mem[i]);
		}
		puts("");

		memset(mem, 0x00, written);
	}
	free(mem);

#else
	perf();
#endif

#ifdef WIN32
	FreeLibrary(gas);
#else
	dlclose(gas);
#endif
	return 0;
}
