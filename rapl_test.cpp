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

//#define PERF
#ifdef PERF
#include <time.h>
#endif

#ifdef WIN32
#include <windows.h>
#else
#include <dlfcn.h>
#endif

#include "argon.h"
#include "support.h"

#define UNUSED(x) ((void)(x))

libhandle_t gas = (libhandle_t)0;

#ifdef __cplusplus
template<typename T>
static void resolveSymbol(const char *sym, T& outSym){
	void *psym = LIB_GETSYM(gas, sym);
	outSym = reinterpret_cast<T>(psym);
}
#else
static void *resolveSymbol(const char *sym){
	return LIB_GETSYM(gas, sym);
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

//#define PERF
#ifdef PERF
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
#endif

int main(int argc, char *argv[]){
	UNUSED(argv);

	if(argc < 2){
		fprintf(stderr, "Usage: %s ./libgas.so\n", argv[0]);
		return EXIT_FAILURE;
	}


	//launchDebugger();

	//setvbuf(stdout, NULL, _IONBF, 0);
	//setvbuf(stderr, NULL, _IONBF, 0);

	gas = LIB_OPEN(argv[1]);
	if(gas == NULL){
		LIB_PERROR(stderr);
		return 1;
	}
	#include "binutils_imports.h"

	uint8_t *mem = argon_init_gas(1024 * 1024,
		ARGON_RESET_FULL | ARGON_FAST_INIT);

#ifdef PERF
	perf();
#else
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
#endif

	free(mem);
	argon_reset_gas(ARGON_RESET_FULL);

	LIB_CLOSE(gas);
	return 0;
}
