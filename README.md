## argon
An experimental project to use binutils as a library

### rapl_test
An example program implementing a Read, Assemble, Print Loop.
 
It can be thought as a hacky JIT compiler based on GAS

#### How does it work?

- `CMakeLists.txt` takes care of downloading and building binutils with the correct flags
- `cc_wrap` is used as the C compiler in order to apply ad-hoc patches that expose the size of private types
- link time wrappers (`wrappers.cpp`) are used to hook binutils functions. This is used to implement a poor man's garbage collector and to allow object files to be written in-memory
- a small helper (`glue.c`) is added to binutils to simplify certain operations, like resetting and initializing GAS