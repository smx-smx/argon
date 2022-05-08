/**
 * SPDX-License-Identifier: GPL-2.0-or-later
 * 
 * @file dynapi.c
 * @author Stefano Moioli <smxdev4@gmail.com>
 * @brief Runtime GAS initialization
 * @version 0.1
 * @date 2022-05-08
 * 
 * @copyright Copyright (c) Stefano Moioli 2022
 * 
 */

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifdef WIN32
#include <windows.h>
#else
#include <dlfcn.h>
#endif

#ifdef WIN32
static HMODULE gas;
#else
static void *gas;
#endif

static void *resolveSymbol(const char *sym){
#ifdef WIN32
	return (void *)GetProcAddress(gas, sym);
#else
	return dlsym(gas, sym);
#endif
}

#define ARGON_DYNINIT
#define BINUTILS_IMPORT_DECL
#include "binutils_imports.h"
#undef BINUTILS_IMPORT_DECL

uint8_t *argon_init_gas(size_t bufferSize){
	#include "binutils_imports.h"
	#ifdef __cplusplus
	#define GVAR(T, sym) \
		T sym; \
		resolveSymbol(#sym, sym)
	#define GFUNC(ret_type, function, ...) \
		ret_type(*function)(__VA_ARGS__); \
		resolveSymbol(#function, function)
	#else
	#define GVAR(T, sym) T sym = (T)resolveSymbol(#sym)
	#define GFUNC(ret_type, function, ...) ret_type(*function)(__VA_ARGS__) = resolveSymbol(#function)
	#endif

	argon_reset_gas();

	uint8_t *mem = (uint8_t *)argon_bfd_data_alloc(bufferSize);

	*stdoutput = bfd_openw("dummy", "default");
	if(*stdoutput == NULL){
		free(mem);
		fprintf(stderr, "bfd_openw() failed\n");
		return NULL;
	}

	_argon_init_gas();
	
	//md_parse_option('V', NULL);

	GVAR(void *, bfd_i386_arch);
	GVAR(void *, bfd_mips_arch);
	GVAR(void *, bfd_riscv_arch);
	GVAR(void *, bfd_rs6000_arch); // PPC

	/** set i386 defaults **/
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

	/** set mips defaults **/
	if(bfd_mips_arch != NULL){
		argon_set_option("mips5", NULL);
		argon_set_option("mips32", NULL);

		// don't emit debug sections (important)
		GVAR(int *, mips_flag_mdebug);
		*mips_flag_mdebug = 0;
	}

	if(bfd_rs6000_arch != NULL){
		// NOTE: requires patch
		GVAR(void *, ppc_hash);
		GVAR(void *, ppc_macro_hash);

		// clear hash tables between invocations to avoid crash
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

	return mem;
}

void argon_assemble(const char *text){
	/**
	 * IMPORTANT: md_assemble modifies the input line
	 * so we must always make a copy 
	 */
	char *line = strdup(text);
	{
		// this writes in the current fragment
		md_assemble(line);
		free(line);
		line = NULL;
	}

	write_object_file();
	if(md_end != NULL) md_end();
}