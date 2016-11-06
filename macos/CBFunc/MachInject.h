
#ifndef _MACH_INJECT_H_
#define _MACH_INJECT_H_

#include <stddef.h> // for ptrdiff_t
#include <sys/types.h>
#include <mach/error.h>
#include <mach/vm_types.h>
#include <Security/Authorization.h>
#include <Security/AuthorizationTags.h>

__BEGIN_DECLS

typedef unsigned char BYTE, *PBYTE;
typedef unsigned long long ULONG, *PULONG;

#define MAX_PATH 260
#define	Err_InjectEntry_ImageNotFound	(err_local|1)

#define INJECT_ENTRY     InjectEntry
#define INJECT_ENTRY_SYM "InjectEntry"

void* RemoteThreadProc( void* pParam );
void InstallHook( ptrdiff_t offset, void* pParam, size_t pSize, void* pDummy);

typedef void (*mach_inject_entry)(ptrdiff_t nCodeOffset, void* pParamBlock, size_t nParamSize, void* pData);


#if defined (__i386__)
void* FetchUpdateNewImage( const void* pMachImage, ULONG nImageSize,
                           ULONG nJumpOffset, ULONG nJumpSize, ptrdiff_t nFixedOffset );
#endif


ULONG FetchImageSize( char* pczImageName, uint32_t nMapSize, PULONG pSize );

mach_error_t FetchMachImage( void* pEntry, void** ppMachImage,
                             PULONG pSize, PULONG pJmpTableOffset, PULONG pJmpTableSize);

mach_error_t MachInject( mach_inject_entry pThreadEntry, void* pParamBlock,
                         size_t nParamSize, pid_t nPID, vm_size_t nStackSize);


void ReleaseTaskportRights();

OSStatus AcquireTaskportRights();
OSStatus AcquireTaskportRightsEx();

OSStatus
AcquireTaskportRights_Interact(AuthorizationRef  pAuthRef, AuthorizationRights TaskRights,
                               AuthorizationFlags nAuthFlags, AuthorizationRights* pOutTaskRights );



__END_DECLS

#endif
