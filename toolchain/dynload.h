#pragma once

#include "syscalls.h"
#include "malloc.h"
#include "defs.h"
#include <sys/types.h>

#define DL_FILE_APPEND_NODE(dev_v, ino_v, tail_ptr) do {\
            DlFileInfo *__node = __dl_malloc(sizeof(DlFileInfo));\
            __node->dev = dev_v; __node->ino = ino_v;\
            __node->next = 0; \
            *tail_ptr = __node; \
            tail_ptr = &(__node->next); \
} while (0)

hidden noplt bool __dl_checkelf(Elf64_Ehdr *ehdr);
hidden noplt DlElfInfo * __dl_loadelf(const char* path);
hidden noplt bool __dl_loadelf_extras(DlElfInfo *ret);
hidden noplt void __dl_parse_dyn(Elf64_Dyn *dyn, uint64_t dynv[]);
