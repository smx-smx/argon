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

#define OPTION_MD_BASE  290
#define OPTION_32 (OPTION_MD_BASE + 0)
#define OPTION_64 (OPTION_MD_BASE + 1)
#define OPTION_DIVIDE (OPTION_MD_BASE + 2)
#define OPTION_MARCH (OPTION_MD_BASE + 3)
#define OPTION_MTUNE (OPTION_MD_BASE + 4)
#define OPTION_MMNEMONIC (OPTION_MD_BASE + 5)
#define OPTION_MSYNTAX (OPTION_MD_BASE + 6)
#define OPTION_MINDEX_REG (OPTION_MD_BASE + 7)
#define OPTION_MNAKED_REG (OPTION_MD_BASE + 8)
#define OPTION_MRELAX_RELOCATIONS (OPTION_MD_BASE + 9)
#define OPTION_MSSE2AVX (OPTION_MD_BASE + 10)
#define OPTION_MSSE_CHECK (OPTION_MD_BASE + 11)
#define OPTION_MOPERAND_CHECK (OPTION_MD_BASE + 12)
#define OPTION_MAVXSCALAR (OPTION_MD_BASE + 13)
#define OPTION_X32 (OPTION_MD_BASE + 14)
#define OPTION_MADD_BND_PREFIX (OPTION_MD_BASE + 15)
#define OPTION_MEVEXLIG (OPTION_MD_BASE + 16)
#define OPTION_MEVEXWIG (OPTION_MD_BASE + 17)
#define OPTION_MBIG_OBJ (OPTION_MD_BASE + 18)
#define OPTION_MOMIT_LOCK_PREFIX (OPTION_MD_BASE + 19)
#define OPTION_MEVEXRCIG (OPTION_MD_BASE + 20)
#define OPTION_MSHARED (OPTION_MD_BASE + 21)
#define OPTION_MAMD64 (OPTION_MD_BASE + 22)
#define OPTION_MINTEL64 (OPTION_MD_BASE + 23)
#define OPTION_MFENCE_AS_LOCK_ADD (OPTION_MD_BASE + 24)
#define OPTION_X86_USED_NOTE (OPTION_MD_BASE + 25)
#define OPTION_MVEXWIG (OPTION_MD_BASE + 26)
#define OPTION_MALIGN_BRANCH_BOUNDARY (OPTION_MD_BASE + 27)
#define OPTION_MALIGN_BRANCH_PREFIX_SIZE (OPTION_MD_BASE + 28)
#define OPTION_MALIGN_BRANCH (OPTION_MD_BASE + 29)
#define OPTION_MBRANCHES_WITH_32B_BOUNDARIES (OPTION_MD_BASE + 30)
#define OPTION_MLFENCE_AFTER_LOAD (OPTION_MD_BASE + 31)
#define OPTION_MLFENCE_BEFORE_INDIRECT_BRANCH (OPTION_MD_BASE + 32)
#define OPTION_MLFENCE_BEFORE_RET (OPTION_MD_BASE + 33)

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

typedef struct _pseudo_type
{
	/* assembler mnemonic, lower case, no '.' */
	const char *poc_name;
	/* Do the work */
	void (*poc_handler) (int);
	/* Value to pass to handler */
	int poc_val;
} pseudo_typeS;

struct option
{
  const char *name;
  /* has_arg can't be an enum because some compilers complain about
     type mismatches in all the code that assumes it is an int.  */
  int has_arg;
  int *flag;
  int val;
};

#define BINUTILS_IMPORT_DECL
#include "binutils_imports.h"
#undef BINUTILS_IMPORT_DECL

void call_pseudo_table(pseudo_typeS *table, const char *name){
	for(pseudo_typeS *p = table; p->poc_name != NULL; p++){
		if(strcmp(p->poc_name, name) != 0) continue;
		if(p->poc_handler != NULL){
			p->poc_handler(p->poc_val);
		}
		break;
	}
}

void call_pseudo(const char *name){
	call_pseudo_table(md_pseudo_table, name);
}


int set_option(const char *optname, const char *value){
	for(struct option *p = md_longopts
		;p->name != NULL
		;p++
	){
		if(!strcmp(p->name, optname)){
			if(p->has_arg && value == NULL) {
				return -1;
			}
			md_parse_option(p->val, value);
			return 0;
		}
	}
	return -1;
}

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
#include "binutils_imports.h"

#define GVAR(T, sym) T sym = (T)resolveSymbol(#sym)
#define GFUNC(ret_type, function, ...) ret_type(*function)(__VA_ARGS__) = resolveSymbol(#function)

	argon_reset_gas();

	// $DEBUG
	breakpoint_me();

	#define MEM_SIZE 1024 * 1024
	unsigned char *mem = argon_bfd_data_alloc(MEM_SIZE);

	*stdoutput = bfd_openw("dummy", "default");
	if(*stdoutput == NULL){
		fprintf(stderr, "bfd_openw() failed\n");
		return 1;
	}

	argon_init_gas();
	
	//md_parse_option('V', NULL);

#ifdef TARGET_MIPS
	set_option("mips5", NULL);
	set_option("mips32", NULL);

	GVAR(int *, mips_flag_mdebug);
	if(mips_flag_mdebug){
		*mips_flag_mdebug = 0;
	}
#endif
	

#ifdef TARGET_INTEL
	set_option("64", NULL);
	set_option("march", "generic64");
	set_option("mmnemonic", "intel");
	set_option("msyntax", "intel");
	set_option("mnaked-reg", NULL);
	
	// switch to CODE64 mode
	//call_pseudo("code64");
	call_pseudo("code32");
#endif

	GFUNC(void, riscv_after_parse_args);
	GFUNC(void, riscv_pop_insert);

	GVAR(char **, input_line_pointer);

	// NOTE: requires patch
	GVAR(void **, riscv_subsets);
	if(riscv_subsets){
		*riscv_subsets = NULL;
	}

	if(riscv_after_parse_args){
		// inits riscv_subsets
		riscv_after_parse_args();
	}

	pseudo_typeS *tc_pseudo_ops = NULL;
	char *line_buf = argon_gcmalloc(32);
	memset(line_buf, 0x00, 32);

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

#if 0
	if(riscv_pop_insert){
		// register riscv pseudo-ops
		riscv_pop_insert();
		tc_pseudo_ops = argon_tc_pseudo_ops();

		// perform a push to rewrite riscv_subsets
		char *saved_lineptr = *input_line_pointer;
		strcpy(line_buf, "push");
		*input_line_pointer = line_buf;
		call_pseudo_table(tc_pseudo_ops, "option");
		*input_line_pointer = saved_lineptr;
	}

	if(riscv_pop_insert){
		// perform a pop to restore riscv_opts_stack
		char *saved_lineptr = *input_line_pointer;
		strcpy(line_buf, "pop");
		*input_line_pointer = line_buf;
		call_pseudo_table(tc_pseudo_ops, "option");
		*input_line_pointer = saved_lineptr;
	}
#endif

	return 0;
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
	assemble("mp .");
	assemble("jmp .");
	//assemble("jmp .");
	//assemble("xor eax, eax");
#endif

#ifdef WIN32
	FreeLibrary(gas);
#else
	dlclose(gas);
#endif
	return 0;
}
