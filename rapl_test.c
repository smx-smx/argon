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

#define _GNU_SOURCE
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

#include <sys/stat.h>

#define UNUSED(x) ((void)(x))

#ifdef WIN32
static HMODULE gas;
#else
static void *gas;
#endif

static void *resolveSymbol(char *sym){
#ifdef WIN32
	return (void *)GetProcAddress(gas, sym);
#else
	return dlsym(gas, sym);
#endif
}

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

static void *gas_handle = NULL;

void breakpoint_me(){
	puts("");
}

int assemble(const char *buffer){
	if(strlen(buffer) < 1) return -1;

#include "binutils_imports.h"

#define GVAR(T, sym) T sym = (T)resolveSymbol(#sym)
#define GFUNC(ret_type, function, ...) ret_type(*function)(__VA_ARGS__) = resolveSymbol(#function)

	argon_reset_gas();

	// $DEBUG
	//breakpoint_me();

	#define MEM_SIZE 1024 * 1024
	unsigned char *mem = argon_bfd_data_alloc(MEM_SIZE);

	*stdoutput = bfd_openw("dummy", "default");
	if(*stdoutput == NULL){
		fprintf(stderr, "bfd_openw() failed\n");
		return 1;
	}

	argon_init_gas();
	
	//md_parse_option('V', NULL);

	GVAR(void *, bfd_i386_arch);
	GVAR(void *, bfd_mips_arch);
	GVAR(void *, bfd_riscv_arch);
	GVAR(void *, bfd_rs6000_arch); // PPC

	if(bfd_i386_arch != NULL){
		argon_set_option("64", NULL);
		argon_set_option("march", "generic64");
		argon_set_option("mmnemonic", "intel");
		argon_set_option("msyntax", "intel");
		argon_set_option("mnaked-reg", NULL);
		
		// switch to CODE64 mode
		//argon_call_pseudo("code64", NULL);
		argon_call_pseudo("code32", NULL);
	}

	if(bfd_mips_arch != NULL){
		argon_set_option("mips5", NULL);
		argon_set_option("mips32", NULL);

		GVAR(int *, mips_flag_mdebug);
		*mips_flag_mdebug = 0;
	}

	if(bfd_rs6000_arch != NULL){
		// NOTE: requires patch
		GVAR(void *, ppc_hash);
		GVAR(void *, ppc_macro_hash);

		if(ppc_hash != NULL){
			argon_clear_htab(ppc_hash);
		}
		if(ppc_macro_hash != NULL){
			argon_clear_htab(ppc_macro_hash);
		}
	}
	
	if(bfd_riscv_arch != NULL){
		GFUNC(void, riscv_after_parse_args);
		GFUNC(void, riscv_pop_insert);

		// NOTE: requires patch
		GVAR(void **, riscv_subsets);
		if(riscv_subsets){
			*riscv_subsets = NULL;
		}

		// inits riscv_subsets
		riscv_after_parse_args();
	}

	md_begin();
	
	/**
	 * IMPORTANT: md_assemble modifies the input line
	 * so we must always make a copy 
	 */
	char *line = strdup(buffer);
	{
		// this writes in the current fragment
		md_assemble(line);
		free(line);
		line = NULL;
	}

	DPRINTF("%p %p %p\n", _frchain_now->frch_root, _frchain_now->frch_last, _frchain_now->frch_next);
	DPUTS("--");

	write_object_file();

	if(md_end != NULL) md_end();

	bfd_close(*stdoutput);

	size_t written = argon_bfd_data_written();
	for(size_t i=0; i<written; i++){
		printf("%02hhx ", mem[i]);
	}
	puts("");	

	return 0;
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
	long millis = 0;
	long opers = 0;
	for(;;++opers){
		struct timespec ts = timer_start();
		assemble("jmp .");
		long diff = timer_end(ts);
		long diff_millis = diff / 1e6;
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

	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);

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

#if 1
	char buffer[128] = {0};
	while(!feof(stdin)){
		fgets(buffer, sizeof(buffer), stdin);
		char *p = strrchr(buffer, '\n');
		if(p) *p = '\0';

		if(!strcmp(buffer, ".quit")){
			break;
		}
		assemble(&buffer[0]);
	}
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
