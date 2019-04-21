# Function Stub Builder
This tool is designed to use radare2 along with a c stub template to hook libc or uClibc main to call a given function in a binary. [Easy Pickings](https://github.com/ChrisTheCoolHut/Easy-Pickings) suffers when not working with relocatable binaries, by using the LD_PRELOAD trick, this tool is designed to work with all linux-based ELFs.

A full use-case of this tool is shown [here](https://breaking-bits.gitbook.io/breaking-bits/vulnerability-discovery/reverse-engineering/modern-approaches-toward-embedded-research)

## Install
The function stub builder just relies on `r2pipe` which in turns requires an install of [radare2](https://github.com/radare/radare2).
```
git clone https://github.com/ChrisTheCoolHut/Function-stub-builder.git
cd Fuction-stub-builder
# If you don't have radare2
git clone https://github.com/radare/radare2.git
cd radare2
sudo ./sys/install.sh
cd ../
# Once radare2 is installed, just install this as python package.
pip install -e .
```
## Usage
```bash
$ stub_builder -h
usage: stub_builder [-h] --File FILE {hardcode,recover} ...

positional arguments:
  {hardcode,recover}    Hardcode or automatically use prototypes and addresses
    hardcode            Use absolute offsets and prototypes
    recover             Use radare2 to recover function address and prototype

optional arguments:
  -h, --help            show this help message and exit
  --File FILE, -F FILE  ELF executable to create stub from

```

The stub builder supports two modes of operation, an automatic recovery mode which uses radare2 to locate a function and auto populate function prototypes information and a manual-hardcoded mode which lets you specify a given function's prototype and function location.

### Recover mode
Using [crackme0x04](https://github.com/angr/angr-doc/raw/master/examples/CSCI-4968-MBE/challenges/crackme0x04/crackme0x04) from the IOLI problem suite we can run stub builder to directly call the flag check function.
```bash
$ stub_builder -F crackme0x04 recover -h
usage: stub_builder recover [-h] {name,addr} ...

positional arguments:
  {name,addr}  Resolve function by name or address
    name       Use function name
    addr       Use function addr

optional arguments:
  -h, --help   show this help message and exit
```

```bash
$ stub_builder -F crackme0x04 recover name check
[+] Modify main_hook.c to call instrumented function
[+] Compile with "gcc main_hook.c -o main_hook.so -fPIC -shared -ldl"
[+] Hook with: LD_PRELOAD=./main_hook.so ./crackme0x04
[+] Created main_hook.c
```
The command above will generate a main_hook.c file. I've modified the output to create the below snippet to run and solve the crackme0x04 challenge
```c
#define _GNU_SOURCE
#include <stdio.h>
#include <dlfcn.h>

//gcc main_hook.c -o main_hook.so -fPIC -shared -ldl


/* Trampoline for the real main() */
static int (*main_orig)(int, char **, char **);

/* Our fake main() that gets called by __libc_start_main() */
int main_hook(int argc, char **argv, char **envp)
{

    //<arg declarations here>
    void (*do_thing_ptr)(char *) = 0x8048484;

    char my_num[10] = {'\x00'};
    for(int i =0; i < 256; i++)
    {
	    sprintf(my_num, "%d", i);
	    printf("Trying password %s\n", my_num);
	    (*do_thing_ptr)(my_num);
    }

    return 0;
}

/*
 * Wrapper for __libc_start_main() that replaces the real main
 * function with our hooked version.
 */
int __libc_start_main(
    int (*main)(int, char **, char **),
    int argc,
    char **argv,
    int (*init)(int, char **, char **),
    void (*fini)(void),
    void (*rtld_fini)(void),
    void *stack_end)
{
    /* Save the real main function address */
    main_orig = main;

    /* Find the real __libc_start_main()... */
    typeof(&__libc_start_main) orig = dlsym(RTLD_NEXT, "__libc_start_main");

    /* ... and call it with our custom main function */
    return orig(main_hook, argc, argv, init, fini, rtld_fini, stack_end);
}
```

The expected output is:
```
$ LD_PRELOAD=./main_hook.so ./crackme0x04
Trying password 0
Password Incorrect!
Trying password 1
Password Incorrect!

..... SNIP ......

Password Incorrect!
Trying password 68
Password Incorrect!
Trying password 69
Password OK!

```

### Hardcode mode
The hardcode mode can be used to do the same thing

```bash
$ stub_builder -F crackme0x04 hardcode -h
usage: stub_builder hardcode [-h]
                             func_addr func_args_prototype func_return_type

positional arguments:
  func_addr            Address of given function
  func_args_prototype  Function prototype arguments as string EX. '(int args,
                       char **argv)'
  func_return_type     Function return type EX. 'int'

optional arguments:
  -h, --help           show this help message and exit

```
```bash
$ stub_builder -F crackme0x04 hardcode 0x08048484 "(char *)" "int"
[+] Modify main_hook.c to call instrumented function
[+] Compile with "gcc main_hook.c -o main_hook.so -fPIC -shared -ldl"
[+] Hook with: LD_PRELOAD=./main_hook.so ./crackme0x04
[+] Created main_hook.c
```
