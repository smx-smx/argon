#ifdef BINUTILS_IMPORT_DECL
#define GVAR(T, sym) T sym = (T)0

#define GFUNC(ret_type, function, ...) \
	ret_type(*function)(__VA_ARGS__) = NULL
#else

#define GVAR(T, sym) sym = (T)resolveSymbol(#sym)
#define GFUNC(ret_type, function, ...) function = resolveSymbol(#function)
#endif

GFUNC(int, md_parse_option, int c, const char *arg);
GFUNC(void, md_begin);
GFUNC(void, md_assemble, char *line);
GFUNC(void, md_end);

GFUNC(void *, bfd_openw, const char *filename, const char *target);
GFUNC(int, bfd_close, void *abfd);
GFUNC(void, write_object_file);

// from wrappers.cpp
GFUNC(void *, argon_bfd_data_alloc, size_t);
GFUNC(size_t, argon_bfd_data_written);
GFUNC(void *, argon_tc_pseudo_ops);

/** globals **/
GVAR(void **, stdoutput);
GVAR(pseudo_typeS *, md_pseudo_table);
GVAR(struct option *, md_longopts);

GFUNC(void, argon_init_gas);
GFUNC(void, argon_reset_gas);
GFUNC(void *, argon_gcmalloc);

#undef GVAR
#undef GFUNC