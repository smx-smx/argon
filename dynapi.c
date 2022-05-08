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
#include "as.h"
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

#include "bfd.h"

#include "argon.h"
#include "argon_api.h"

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

static void *resolveSymbol(const char *sym);

extern int __argon_tls_init();

#ifdef WIN32
static HMODULE gas;

BOOL WINAPI DllMain(
    HINSTANCE hinstDLL,
    DWORD fdwReason,   
    LPVOID lpReserved )
{
switch( fdwReason ) { 
        case DLL_PROCESS_ATTACH:
			// store the DLL handle for dynamic symbol lookup
			gas = hinstDLL;
			/**
			 * https://github.com/msys2/MINGW-packages/issues/2519
			 * 
			 * At the very first access of a thread-local object in a new program,
			 * emutls_init is called via __emutls_get_address.
			 * This function allocates some memory for the storage using malloc (see emutls_alloc),
			 * and registers emutls_destroy to be executed at thread exit, using __gthread_key_create.
			 **/
			__argon_tls_init();
			/**
			 * now that ctors and TLS have been taken care of,
			 * we can enable GC malloc
			 **/
			argon_gc_enable(1);
            break;
        case DLL_THREAD_ATTACH:
            break;
        case DLL_THREAD_DETACH:
            break;
        case DLL_PROCESS_DETACH:
            break;
    }
    return TRUE;  // Successful DLL_PROCESS_ATTACH.
}
#else
void __attribute__((constructor)) ctor(){
	__argon_tls_init();
	argon_gc_enable(1);
}
#endif

static void *resolveSymbol(const char *sym){
#ifdef WIN32
	return (void *)GetProcAddress(gas, sym);
#else
	return dlsym(RTLD_DEFAULT, sym);
#endif
}

extern void _argon_init_gas(unsigned flags);

enum argon_arch {
	ARCH_UNKNOWN,
	ARCH_I386,
	ARCH_MIPS,
	ARCH_RISCV,
	ARCH_PPC,
	ARCH_Z80
};

static int argon_arch_detect(){
	GVAR(void *, bfd_i386_arch);
	if(bfd_i386_arch) return ARCH_I386;

	GVAR(void *, bfd_mips_arch);
	if(bfd_mips_arch) return ARCH_MIPS;

	GVAR(void *, bfd_riscv_arch);
	if(bfd_riscv_arch) return ARCH_RISCV;

	GVAR(void *, bfd_rs6000_arch); // PPC
	if(bfd_rs6000_arch) return ARCH_PPC;

	GVAR(void *, bfd_z80_arch);
	if(bfd_z80_arch) return ARCH_Z80;

	return ARCH_UNKNOWN;
}

uint8_t *argon_init_gas(size_t bufferSize, unsigned flags){
	argon_reset_gas(flags);

	uint8_t *mem = NULL;
	if(!HAS_FLAG(flags, ARGON_KEEP_BUFFER)){
		mem = (uint8_t *)argon_bfd_data_alloc(bufferSize);
	}

	stdoutput = bfd_openw("dummy", "default");
	if(stdoutput == NULL){
		free(mem);
		fprintf(stderr, "bfd_openw() failed\n");
		return NULL;
	}

	_argon_init_gas(flags);
	
	//md_parse_option('V', NULL);

	if(!HAS_FLAG(flags, ARGON_SKIP_INIT)){
	int arch = argon_arch_detect();
		switch(arch){
			case ARCH_I386:;
				argon_set_option("64", NULL);
				//argon_set_option("march", "generic64");
				argon_set_option("mmnemonic", "intel");
				argon_set_option("msyntax", "intel");
				argon_set_option("mnaked-reg", NULL);

				// switch to CODE64 mode
				argon_call_pseudo("code64", NULL);
				//argon_call_pseudo("code32", NULL);
				break;
			case ARCH_MIPS:;
				argon_set_option("mips5", NULL);
				argon_set_option("mips32", NULL);

				// don't emit debug sections (important)
				GVAR(int *, mips_flag_mdebug);
				*mips_flag_mdebug = 0;
				break;
			case ARCH_PPC:;
				// NOTE: requires patch
				GVAR(htab_t *, ppc_hash);
				GVAR(htab_t *, ppc_macro_hash);

				// clear hash tables between invocations to avoid crash
				if(ppc_hash != NULL){
					memset(ppc_hash, 0x00, sizeof(*ppc_hash));
				}
				if(ppc_macro_hash != NULL){
					memset(ppc_macro_hash, 0x00, sizeof(*ppc_macro_hash));
				}
				break;
			case ARCH_RISCV:;
				GFUNC(void, riscv_after_parse_args);
				GFUNC(void, riscv_pop_insert);

				// NOTE: requires patch
				GVAR(void **, riscv_subsets);
				if(riscv_subsets){
					*riscv_subsets = NULL;
				}

				// inits riscv_subsets
				riscv_after_parse_args();
				break;
			case ARCH_Z80:;
				// enable all instructions
				// $FIXME: some instructions (e.g. dec) complain about illegal operand
				argon_set_option("full", NULL);
				break;
		}

		int fast_init = HAS_FLAG(flags, ARGON_FAST_INIT);
		if(fast_init){
			argon_gcpool_set(ARGON_POOL_INIT);
		}
		md_begin();
		if(fast_init){
			argon_gcpool_set(ARGON_POOL_LIVE);
		}
	}

	return mem;
}

void argon_assemble(const char *text){
	/**
	 * IMPORTANT: md_assemble modifies the input line
	 * so we must always make a copy 
	 */
	char *line = argon_strdup(text);
	{
		// this writes in the current fragment
		md_assemble(line);
		argon_free(line);
		line = NULL;
	}

	/**
	 * we write immediately, to capture the output
	 * intermediate output is complicated to achieve,
	 * due to certain operations being delayed due to relaxation
	 **/
	write_object_file();
}
