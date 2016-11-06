
#include "MachHook.h"
#include <mach-o/fat.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <strings.h>
#include <errno.h>
#include <fcntl.h>


#if defined(__x86_64__)

    #undef MH_MAGIC
    #define MH_MAGIC MH_MAGIC_64

    #undef CPU_TYPE_I386
    #define CPU_TYPE_I386 CPU_TYPE_X86_64

    #undef LC_SEGMENT
    #define LC_SEGMENT LC_SEGMENT_64

    #define mach_header mach_header_64
    #define nlist nlist_64
    #define segment_command segment_command_64
    #define section section_64

#endif


#define OPCODE_JMP  '\xE9'
#define INVALID_OFFSET  1
#define DATA_SEG_NAME   "__DATA"
#define LAZY_SECT_NAME  "__la_symbol_ptr"
#define IMPORT_SEG_NAME "__IMPORT"
#define JUMP_SECT_NAME  "__jump_table"


CMachHook::CMachHook()
{
}

CMachHook::~CMachHook()
{
}

void*
CMachHook::ReadFile( int fd, size_t nOffset, size_t nCount )
{
    void* pReturn = NULL;
    
    if(lseek( fd, nOffset, SEEK_SET) < 0) return 0;
    
    pReturn = malloc( nCount );
    if(!pReturn || read( fd, pReturn, nCount) != nCount)
    {
        free( pReturn );
        return 0;
    }
    return pReturn;
}

uint32_t
CMachHook::ReadHeaderOffset(int nDesc)
{
    return 0;
}


void*
CMachHook::MachHook_Init()
{
    return NULL;
}

void CMachHook::MachHook_Free()
{
    
}

void*
CMachHook::MachHook_Func(void* pHandle, char* pczFuncName)
{
    return NULL;
}


