#pragma once
#include <stdint.h>
#include <stddef.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <stdbool.h>
#include <elf.h>

#define hidden 
#define noplt __attribute__((noplt))
#define noreturn __attribute__((noreturn))

typedef struct env_ld_config {
    const char* preload;
    const char* lib_path;
} EnvLdConfig;

typedef struct str_list_node {
    const char* s;
    struct str_list_node* next;
} SLNode;

struct tls_module {
	struct tls_module *next;
	void *image;
	size_t len, size, align, offset;
};

struct __pthread {
	/* Part 1 -- these fields may be external or
	 * internal (accessed via asm) ABI. Do not change. */
	struct pthread *self;
	uintptr_t *dtv;
	struct pthread *prev, *next;
	uintptr_t sysinfo;
	uintptr_t canary;

	// The rest are used by libc itself.
	char __padding[200 - sizeof(uintptr_t) * 6];
};

typedef struct dl_file_info {
    dev_t dev;
    ino_t ino;
    struct dl_file_info *next;
} DlFileInfo;

typedef struct dl_elf_info {
    dev_t dev;
    ino_t ino;
    uint16_t elf_type;
    size_t base;
    Elf64_Phdr* ph;
    int64_t phnum;

    // below are extras; they can be loaded by calling __dl_loadelf_extras()
    Elf64_Dyn* dyn;
    SLNode* dep_names;
    char *str_table;
    Elf64_Sym *sym_table;
    char *runpath;
    void* gnu_hash_table;
    const char *load_path;
    struct tls_module tls; /* TLS initial image for this DSO */

    uint64_t shoff;		/* Section header table offset */
    uint16_t shentsize;	/* Section header table entry size */
    uint16_t shnum;		/* Section header table entry count */
    uint16_t shstrndx;	/* Section header string table index */

    DlFileInfo *deps;
    bool relocated;
    int (*entry)();
} DlElfInfo;
