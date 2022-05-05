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

struct obstack          /* control current object in current chunk */
{
  size_t chunk_size;     /* preferred size to allocate chunks in */
  void *chunk; /* address of current struct obstack_chunk */
  char *object_base;            /* address of object we are building */
  char *next_free;              /* where to add next char to current object */
  char *chunk_limit;            /* address of char after current chunk */
};

typedef struct frchain			/* control building of a frag chain */
{				/* FRCH = FRagment CHain control */
  void *frch_root;	/* 1st struct frag in chain, or NULL */
  void *frch_last;	/* last struct frag in chain, or NULL */
  void *frch_next;	/* next in chain of struct frchain-s */
  int frch_subseg;		/* subsegment number of this chain */
  void *fix_root;		/* Root of fixups for this subsegment.  */
  void *fix_tail;		/* Last fixup for this subsegment.  */
  struct obstack frch_obstack;	/* for objects in this frag chain */
  // don't care
  //void *frch_frag_now;		/* frag_now for this subsegment */
  //void *frch_cfi_data;
} frchainS;

static void *resolveSymbol(char *sym){
#ifdef WIN32
	return (void *)GetProcAddress(gas, sym);
#else
	return dlsym(gas, sym);
#endif
}

#define GVAR(T, sym) T sym = (T)resolveSymbol(#sym)

#define GFUNC(ret_type, function, ...) \
	ret_type(*function)(__VA_ARGS__) = resolveSymbol(#function)

static void *iovec_open (void *nbfd, void *open_closure){
	UNUSED(nbfd);
	return open_closure;
}
static off_t iovec_read(
	void *nbfd, void *stream, void *buf,
	off_t nbytes, off_t offset
){
	UNUSED(nbfd);
	unsigned char *mem = (unsigned char *)stream;
	memcpy(buf, &mem[offset], nbytes);
	return nbytes;
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

void call_pseudo(pseudo_typeS *table, const char *name){
	for(pseudo_typeS *p = table; p->poc_name != NULL; p++){
		if(strcmp(p->poc_name, name) != 0) continue;
		if(p->poc_handler != NULL){
			p->poc_handler(p->poc_val);
		}
		break;
	}
}

#if 1
#define DPRINTF(fmt, ...)
#define DPUTS(str)
#else
#define DPRINTF(fmt, ...) printf(fmt, __VA_ARGS__)
#define DPUTS(str) puts(str)
#endif

void print_frchain(frchainS *chain, int wipe){
	DPRINTF("%p %p %p\n", chain->frch_root, chain->frch_last, chain->frch_next);

	struct obstack *ob = &chain->frch_obstack;
	DPRINTF("%p\n", ob->chunk_size);
  	DPRINTF("%p\n", ob->chunk);
  	DPRINTF("%p\n", ob->object_base);
  	DPRINTF("%p\n", ob->next_free);
  	DPRINTF("%p\n", ob->chunk_limit);

	unsigned size = ob->next_free - ob->object_base;
	unsigned char *p;
	unsigned i;
	
	for(p = (unsigned char *)ob->object_base, i=0; i<size ; i++, p++){
		DPRINTF("%02hhx ", *p);
	}
	DPUTS("");

	if(wipe) {
		memset(ob->object_base, 0x00, size);
		ob->next_free = ob->object_base;
	}
}

void obstack_mark_empty(struct obstack *ob){
	ob->next_free = ob->object_base;
}

// get and clear
void *gc_frchain(frchainS *chain, unsigned *pSize){
	print_frchain(chain, 0);
	
	struct obstack *ob = &chain->frch_obstack;
	unsigned size = ob->next_free - ob->object_base;

	unsigned char *mem = calloc(size, 1);
	memcpy(mem, ob->object_base, size);
	memset(ob->object_base, 0x00, size);
	
	obstack_mark_empty(ob);

	if(pSize != NULL){
		*pSize = size;
	}
	return mem;
}


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
	GFUNC(void, subsegs_begin);
	GFUNC(void, symbol_begin);
	GFUNC(void, read_begin);
	GFUNC(void, expr_begin);
	GFUNC(void, dot_symbol_init);

	GFUNC(void *, subseg_new, const char *segname, int subseg);
	GFUNC(void, bfd_set_section_flags, void *, unsigned);
	GFUNC(void, subseg_set, void *, int);

	GFUNC(int, md_parse_option, int c, const char *arg);
	GFUNC(void, md_begin);
	GFUNC(void, md_assemble, char *line);
	GFUNC(void, md_end);

	GFUNC(void *, bfd_openr_iovec,
		const char *filename, const char *target,
		void *(*open) (void *nbfd, void *open_closure),
		void *open_closure,
		off_t (*pread) (
			void *nbfd,
			void *stream, void *buf,
			off_t nbytes, off_t offset),
		int (*close) (void *nbfd, void *stream),
		int (*stat) (void *abfd, void *stream, struct stat *sb)
	);

	GFUNC(void *, bfd_openw, const char *filename, const char *target);

	GFUNC(int, bfd_close, void *abfd);

	// from wrappers.cpp
	GFUNC(void *, argon_bfd_data_alloc, size_t);
	GFUNC(size_t, argon_bfd_data_written);

	/** globals **/
	GVAR(void **, stdoutput);
	GVAR(pseudo_typeS *, md_pseudo_table);
	GVAR(void **, text_section);

	GVAR(frchainS **, frchain_now);
	GVAR(void **, now_seg);
	GVAR(void **, now_subseg);
	GVAR(void **, frag_now);

	GVAR(void *, _bfd_std_section);
	GVAR(void *, predefined_address_frag);

	GFUNC(void *, local_symbol_make,
		const char *name, void *section, void *frag, uintptr_t val);

	GFUNC(void, subseg_change, void *seg, int subseg);

	GFUNC(void, argon_init_gas);
	GFUNC(void, argon_reset_gas);
	
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
	
	md_parse_option('V', NULL);

	md_parse_option(OPTION_64, NULL);
	//md_parse_option(OPTION_MARCH, "generic64");
	md_parse_option(OPTION_MMNEMONIC, "intel");
	md_parse_option(OPTION_MSYNTAX, "intel");
	md_parse_option(OPTION_MNAKED_REG, NULL);

	// switch to CODE64 mode
	//call_pseudo(md_pseudo_table, "code64");
	call_pseudo(md_pseudo_table, "code32");

	/**
	 * create the .text section 
	 */
	*text_section = subseg_new(".text", 0);
	//bfd_set_section_flags(*text_section, 1 | 2 | /*4 |*/ 0x10 |8);
	//bfd_set_section_flags(*text_section, 1 | 2 | /*4 |*/ 0x10 |8);
	bfd_set_section_flags(*text_section, 1 | 2 | 4 | 0x10 |8);

	// read the current fragment chain (aka of the .text section)
	frchainS *_frchain_now = *frchain_now;
	void *_frag_now = *frag_now;

	/**
	 * reset the current pointers to the .text section
	 * for the upcoming assemble operation
	 **/
	*frchain_now = _frchain_now;
	*frag_now = _frag_now;

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

	GFUNC(void, write_object_file);
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
