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
#include "symbols.h"
#include "obstack.h"

#include <stdlib.h>

#define CLEAR(x) memset(&x, 0x00, sizeof(x))
#define CLEAR_SYMBOL(x) memset(&x, 0x00, __argon_get_symbol_size())

extern struct xsymbol dot_symbol_x;
extern size_t __argon_get_symbol_size();

// free all memory allocated by GAS
extern void argon_malloc_gc();

//#define ABSOLUTE_JUMPS
#define TEXT_FLAGS (SEC_ALLOC | SEC_LOAD | /*SEC_RELOC |*/ SEC_CODE | SEC_READONLY)

static struct elf_obj_tdata fake_tdata;

void *argon_gcmalloc(size_t sz){
	// in binutils context, malloc is overridden by wrapper.cpp
	return malloc(sz);
}

void *argon_gczalloc(size_t sz){
	void *mem = argon_gcmalloc(sz);
	if(mem == NULL){
		return NULL;
	}
	memset(mem, 0x00, sz);
	return mem;
}

void argon_clear_htab(htab_t *htab){
	memset(htab, 0x00, sizeof(*htab));
}

void argon_init_gas(){
	symbol_begin();
	subsegs_begin();
	// initializes obstacks
	read_begin();
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
}

void argon_reset_gas(){
	bfd_cache_close_all();
	argon_malloc_gc();

	now_seg = NULL;
	now_subseg = 0;
	frchain_now = NULL;
	frag_now = NULL;

	text_section = NULL;
	reg_section = NULL;
	expr_section = NULL;

	stdoutput = NULL;
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
}