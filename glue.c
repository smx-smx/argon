/**
 * SPDX-License-Identifier: GPL-2.0-or-later
 * 
 * @file glue.c
 * @author Stefano Moioli <smxdev4@gmail.com>
 * @brief interface between GAS internals and the outer world
 * @version 0.1
 * @date 2022-05-05
 * 
 * @copyright Copyright (c) Stefano Moioli 2022
 */
#include "as.h"
#include "subsegs.h"
#include "obstack.h"

#include <stdlib.h>

#include "argon.h"
#include "argon_api.h"

#ifdef WIN32
// libiberty requires this for some odd reasons
int fork (void){
	fputs("fork() not supported on Windows\n", stderr);
	fflush(stderr);
	abort();
}
#endif

#define CLEAR(x) memset(&x, 0x00, sizeof(x))
#define CLEAR_SYMBOL(x) memset(&x, 0x00, __argon_get_symbol_size())

extern struct xsymbol dot_symbol_x;
extern size_t __argon_get_symbol_size();

// free all memory allocated by GAS
extern void argon_malloc_gc();

extern struct option md_longopts[];

//#define ABSOLUTE_JUMPS
#define TEXT_FLAGS (SEC_ALLOC | SEC_LOAD | /*SEC_RELOC |*/ SEC_CODE | SEC_READONLY)

static struct elf_obj_tdata fake_tdata;

void *argon_gcmalloc(size_t sz){
	// in binutils context, malloc is overridden by wrapper.cpp
	return malloc(sz);
}

static char *fake_line_buffer = NULL;

extern void *__real_malloc(size_t sz);
extern void __real_free(void *ptr);

void *argon_malloc(size_t sz){
	return __real_malloc(sz);
}
void argon_free(void *ptr){
	__real_free(ptr);
}

char *argon_strdup(const char *str){
	int l = strlen(str);
	char *mem = (char *)argon_malloc(l + 1);
	memcpy(mem, str, l);
	mem[l] = '\0';
	return mem;
}

void *argon_gczalloc(size_t sz){
	void *mem = argon_gcmalloc(sz);
	if(mem == NULL){
		return NULL;
	}
	memset(mem, 0x00, sz);
	return mem;
}

extern struct htab *po_hash;
struct po_entry
{
  const char *poc_name;
  const pseudo_typeS *pop;
};

typedef struct po_entry po_entry_t;

static const pseudo_typeS *
argon_po_entry_find (const char *poc_name){
  po_entry_t needle = { poc_name, NULL };
  po_entry_t *entry = htab_find (po_hash, &needle);
  return entry != NULL ? entry->pop : NULL;
}

int argon_call_pseudo(const char *op, char *args){
	const pseudo_typeS *entry = argon_po_entry_find(op);
	if(entry == NULL){
		return -1;
	}

	char *args_copy = NULL;

	// set line pointer to op arguments
	if(args == NULL){
		input_line_pointer = fake_line_buffer;
	} else {
		int n = strlen(args) + 1;
		args_copy = argon_malloc(n);
		memcpy(args_copy, args, n);

		input_line_pointer = args_copy;
	}
	entry->poc_handler(entry->poc_val);

	if(args_copy != NULL){
		argon_free(args_copy);
	}
	return 0;
}

void _argon_init_gas(unsigned flags){
	symbol_begin();
	subsegs_begin();
	
	if(!HAS_FLAG(flags, ARGON_SKIP_INIT)){
		int fast_init = HAS_FLAG(flags, ARGON_FAST_INIT);
		if(fast_init){
			argon_gcpool_set(ARGON_POOL_INIT);
		}
		read_begin();
		if(fast_init){
			argon_gcpool_set(ARGON_POOL_LIVE);
		}
	} else {
		obstack_free (&notes, NULL);
		obstack_free (&cond_obstack, NULL);
		obstack_begin (&notes, chunksize);
		obstack_begin (&cond_obstack, chunksize);
	}
	expr_begin();

#ifdef ABSOLUTE_JUMPS
	text_section = subseg_new (TEXT_SECTION_NAME, 0);

	frchainS *text_frchain = frchain_now;
	fragS *text_frag = frag_now;
#endif

	data_section = subseg_new (DATA_SECTION_NAME, 0);
  	bss_section = subseg_new (BSS_SECTION_NAME, 0);

	segT abs_section = subseg_new (BFD_ABS_SECTION_NAME, 0);
  	segT und_section = subseg_new (BFD_UND_SECTION_NAME, 0);

  	reg_section = subseg_new ("*GAS `reg' section*", 0);
  	expr_section = subseg_new ("*GAS `expr' section*", 0);

	dot_symbol_init();

	flag_always_generate_output = 1;

#ifdef ABSOLUTE_JUMPS
	/**
	 * set the current pointers to the .text section
	 * for the upcoming assemble operation
	 **/
	frchain_now = text_frchain;
	frag_now = text_frag;
#else
	text_section = subseg_new (TEXT_SECTION_NAME, 0);
#endif

	bfd_set_section_flags (text_section, TEXT_FLAGS);
	bfd_set_section_alignment(text_section, 0);


	// set fake output_elf_obj_tdata
	fake_tdata.o = argon_gczalloc(sizeof(struct output_elf_obj_tdata));

	// set fake ELF data
	elf_tdata(stdoutput) = &fake_tdata;

	fake_line_buffer = argon_gczalloc(32);
}

void argon_reset_gas(unsigned flags){
	if(stdoutput != NULL){
		bfd_close(stdoutput);
		stdoutput = NULL;
		bfd_cache_close_all();
	}

	if(!HAS_FLAG(flags, ARGON_SKIP_GC)){	
		int pools_to_clear = ARGON_POOL_LIVE;
		if(HAS_FLAG(flags, ARGON_RESET_FULL)){
			pools_to_clear |= ARGON_POOL_INIT;
		}
		argon_malloc_gc(pools_to_clear);
	}

	now_seg = NULL;
	now_subseg = 0;
	frchain_now = NULL;
	frag_now = NULL;

	reg_section = NULL;
	expr_section = NULL;

	symbol_table_frozen = 0;
	finalize_syms = 0;

	abs_section_sym = NULL;
	abs_section_offset = 0;

	// don't pad sections
	do_not_pad_sections_to_alignment = 1;
	
	CLEAR(cond_obstack);
	CLEAR(notes);
	
	CLEAR_SYMBOL(abs_symbol);
	CLEAR_SYMBOL(dot_symbol);
	CLEAR_SYMBOL(dot_symbol_x);

	bfd_com_section_ptr->userdata = NULL;
	bfd_ind_section_ptr->userdata = NULL;
	bfd_abs_section_ptr->userdata = NULL;
	bfd_und_section_ptr->userdata = NULL;

	CLEAR(fake_tdata);

	fake_line_buffer = NULL;
}

int argon_set_option(const char *optname, const char *value){
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