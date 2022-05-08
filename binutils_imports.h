#ifdef BINUTILS_IMPORT_DECL

#ifdef BINUTILS_IMPORT_GLOBAL
#define BINUTILS_IMPORT_STATIC
#else
#define BINUTILS_IMPORT_STATIC static
#endif

#define GVAR(T, sym) BINUTILS_IMPORT_STATIC T sym = (T)0

#define GFUNC(ret_type, function, ...) \
	BINUTILS_IMPORT_STATIC ret_type(*function)(__VA_ARGS__) = NULL
#else // BINUTILS_IMPORT_DECL

#ifdef __cplusplus
#define GVAR(T, sym) resolveSymbol(#sym, sym)
#define GFUNC(ret_type, function, ...) resolveSymbol(#function, function)
#else // __cplusplus
#define GVAR(T, sym) sym = (T)resolveSymbol(#sym)
#define GFUNC(ret_type, function, ...) function = resolveSymbol(#function)
#endif

#endif

GFUNC(int, md_parse_option, int c, const char *arg);
GFUNC(void, md_begin);
GFUNC(void, md_assemble, char *line);
GFUNC(void, md_end);

GFUNC(void *, bfd_openw, const char *filename, const char *target);
GFUNC(int, bfd_close, void *abfd);
GFUNC(void, write_object_file);

/** from wrappers.cpp **/
GFUNC(void *, argon_bfd_data_alloc, size_t);
GFUNC(size_t, argon_bfd_data_written);
GFUNC(void *, argon_tc_pseudo_ops);

/** globals **/
GVAR(void **, stdoutput);

/** from glue.c **/
#ifdef ARGON_DYNINIT
GFUNC(void, _argon_init_gas);
#else
GFUNC(unsigned char *, argon_init_gas, size_t mem_size, unsigned flags);
GFUNC(void, argon_assemble, const char *);
GFUNC(void, argon_assemble_end);
GFUNC(void, argon_fseek, long offset, int whence);
#endif
GFUNC(void, argon_reset_gas, unsigned flags);
GFUNC(void *, argon_gcmalloc);
GFUNC(void, argon_clear_htab, void *htab);
GFUNC(void, argon_call_pseudo, const char *name, const char *args);
GFUNC(int, argon_set_option, const char *optname, const char *value);

#undef GVAR
#undef GFUNC
#undef BINUTILS_IMPORT_STATIC