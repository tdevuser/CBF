
#include "MachInject.h"
#include <mach-o/dyld.h>
#include <mach-o/getsect.h>
#include <mach-o/fat.h> // for fat structure decoding
#include <mach-o/arch.h> // to know which is local arch
#include <mach/mach.h>
#include <mach/MACH_ERROR.h>
#include <sys/types.h> // for mmap()
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/errno.h>
#include <dlfcn.h>
#include <assert.h>
#include <stdlib.h> // for malloc()
#include <stdio.h>  // for printf()
#include <fcntl.h> // for open/close
#include <unistd.h>
#include <pthread.h>

#define MACH_ERROR(msg, err) { if(err != err_none) mach_error(msg, err); }

char
InjectCode_X86[] =
"\x55"
"\x8B\xEC";

char
InjectCode_X64[] =
//"\xcc"                           //  int3
"\x90"				// nop..
"\x55"                           // pushq  %rbp
"\x48\x89\xe5"                   // movq   %rsp, %rbp
"\x48\x83\xec\x20"               // subq   $32, %rsp
"\x89\x7d\xfc"                   // movl   %edi, -4(%rbp)
"\x48\x89\x75\xf0"               // movq   %rsi, -16(%rbp)
"\xb0\x00"                                    // movb   $0, %al
// call pthread_set_self
"\x48\xbf\x00\x00\x00\x00\x00\x00\x00\x00"    // movabsq $0, %rdi
"\x48\xb8" "_PTHRDSS"                           // movabsq $140735540045793, %rax
"\xff\xd0"                                    //    callq  *%rax
"\x48\xbe\x00\x00\x00\x00\x00\x00\x00\x00"    // movabsq $0, %rsi
"\x48\x8d\x3d\x2c\x00\x00\x00"                // leaq   44(%rip), %rdi
// DLOpen...
"\x48\xb8" "DLOPEN__" // movabsq $140735516395848, %rax
"\x48\xbe\x00\x00\x00\x00\x00\x00\x00\x00" //  movabsq $0, %rsi
"\xff\xd0"                       //   callq  *%rax
// Sleep(1000000)...
"\x48\xbf\x00\xe4\x0b\x54\x02\x00\x00\x00" //  movabsq $10000000000, %rdi
"\x48\xb8" "SLEEP___" // movabsq $140735516630165, %rax
"\xff\xd0"            //              callq  *%rax
// plenty of space for a full path name here
"LIBLIBLIBLIB" "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
;


/*******************************************************************************
 *
 *	Interface
 *
 *******************************************************************************/
#pragma mark	-
#pragma mark	(Interface)

extern "C" void __pthread_set_self(void*);

void*
RemoteThreadProc(void* pParam)
{
    void* pHandle = NULL;
    
    if(!pParam)
    {
        printf("[%s] Invalid Parameter. == null \n", __FUNCTION__ );
        return NULL;
    }
    
    pHandle = dlopen( (char*)pParam, RTLD_NOW );
    if(!pHandle)
    {
        printf("Could not load patch bundle: %s\n", dlerror());
        fprintf(stderr, "Could not load patch bundle: %s\n", dlerror());
    }
    else
    {
        // dlclsoe( pHandle );
    }
    return 0;
}




void InstallHook( ptrdiff_t offset, void* pParam, size_t pSize, void* pDummy)
{
    __pthread_set_self(pDummy);
    
    int       nPolicy = 0;
    pthread_t pThread = NULL;
    struct sched_param sched;
    
    pthread_attr_t  Attr;
    pthread_attr_init( &Attr );
    pthread_attr_getschedpolicy(  &Attr, &nPolicy );
    pthread_attr_setdetachstate(  &Attr, PTHREAD_CREATE_DETACHED );
    pthread_attr_setinheritsched( &Attr, PTHREAD_EXPLICIT_SCHED  );
    
    sched.sched_priority = sched_get_priority_max( nPolicy );
    pthread_attr_setschedparam( &Attr, &sched );
    
    
    pthread_create( &pThread, &Attr, RemoteThreadProc, pParam );
    
    
    pthread_attr_destroy( &Attr );
    thread_suspend( mach_thread_self() );
}





ULONG
FetchImageSize( char* pczImageName, uint32_t nMapSize, PULONG pSize )
{
    int       nFd        = 0;
    ULONG     nImageSize = 0;
    uint32_t  nMagic     = 0;
    uint32_t  nMagic2    = 0;
    void*     pFileImage = NULL;
    struct fat_header* pFatHeader   = NULL;
    struct fat_arch*   pArch        = NULL;
    struct fat_arch*   pMatchArch   = NULL;
    NXArchInfo*        pCurArchInfo = NULL;
    
    nFd = open( pczImageName, O_RDONLY );
    if(nFd <= 0) return 0;

    pFileImage = mmap( NULL, nMapSize, PROT_READ, MAP_FILE | MAP_SHARED, nFd, 0 );
    if(!pFileImage || pFileImage == MAP_FAILED)
    {
        close( nFd );
        return 0;
    }

    pFatHeader = (struct fat_header*)pFileImage;
    nMagic  = OSSwapBigToHostInt32(FAT_MAGIC);
    nMagic2 = OSSwapBigToHostInt32(FAT_CIGAM);
    if(pFatHeader->magic == nMagic || pFatHeader->magic == nMagic2)
    {
        uint32_t nPos=0, nMaxPos=0;
        
        pCurArchInfo = (NXArchInfo*)NXGetLocalArchInfo();
        pArch = (struct fat_arch*)((ULONG)pFileImage + sizeof(struct fat_header) );
        nMaxPos = OSSwapBigToHostInt32( pFatHeader->nfat_arch );
        for(nPos=0; nPos < nMaxPos; nPos++)
        {
            cpu_type_t    cpuType    = OSSwapBigToHostInt32( pArch[nPos].cputype );
            cpu_subtype_t cpuSubType = OSSwapBigToHostInt32( pArch[nPos].cpusubtype );
            if(pCurArchInfo->cputype == cpuType)
            {
                pMatchArch = (struct fat_arch*)((ULONG)pArch + nPos);
                if(pCurArchInfo->cpusubtype == cpuSubType)
                {
                    break;
                }
            }
        }
        
        if(pMatchArch)
        {
            nImageSize = OSSwapBigToHostInt32( pMatchArch->size );
            if(pSize)
            {
                *pSize = nImageSize;
            }
        }
    }
    
    munmap( pFileImage, nMapSize );
    close( nFd );
    return nImageSize;
}


mach_error_t
FetchMachImage(void* pEntry, void** ppMachImage, PULONG pSize, PULONG pJmpTableOffset, PULONG pJmpTableSize)
{
    mach_error_t nError = 0;
    long     nStart=0, nStop=0;
    ULONG    nEntryPos = 0;
    uint32_t nIndex=0, nMaxCount=0;

#if defined (__i386__)
    struct mach_header*    pHeader  = NULL;
    struct section*        pSection = NULL;
#elif defined(__x86_64__)
    struct mach_header_64* pHeader  = NULL;
    struct section_64*     pSection = NULL;
#endif
    
    if(!pEntry || !ppMachImage) return KERN_INVALID_ARGUMENT;
    
    nEntryPos = (ULONG)pEntry;
    if(pJmpTableOffset && pJmpTableSize)
    {
        *pJmpTableOffset = 0;
        *pJmpTableSize   = 0;
    }
    
    nMaxCount = _dyld_image_count();
    for(nIndex=0; nIndex<nMaxCount; nIndex++)
    {
#if defined (__i386__)
        pHeader = (struct mach_header*)_dyld_get_image_header( nIndex );
        if(!pHeader) continue;
        pSection = (struct section*)getsectbynamefromheader( pHeader, SEG_TEXT, SECT_TEXT );
#elif defined(__x86_64__)
        pHeader = (struct mach_header_64*)_dyld_get_image_header( nIndex );
        if(!pHeader) continue;
        pSection = (struct section_64*)getsectbynamefromheader_64( pHeader, SEG_TEXT, SECT_TEXT );
#endif
        if(!pSection) continue;
        
        nStart = pSection->addr + _dyld_get_image_vmaddr_slide( nIndex );
        nStop  = nStart + pSection->size;
        
        // printf("Start=%p, Header=%p, ImageName=%s \n", (void*)nStart, pHeader, _dyld_get_image_name(nIndex) );
        
        if(nEntryPos >= nStart && nEntryPos <= nStop)
        {
            struct stat sb;
            const char* pczImageName = _dyld_get_image_name( nIndex );
            // printf("ImageName: %s \n", pczImageName );
            
            //	It is truely insane we have to stat() the file system in order to discover the size of an in-memory data structure.
            memset( &sb, 0, sizeof(sb) );
            if(stat(pczImageName, &sb))
            {
                return unix_err( errno );
            }
            
            if(ppMachImage)
            {
                *ppMachImage = (void*)pHeader;
            }
            
            if(pSize)
            {
                *pSize = sb.st_size;
                FetchImageSize( (char*)pczImageName, (uint32_t)sb.st_size, pSize );
            }
            
#if defined (__i386)
            if(pJmpTableOffset && pJmpTableSize)
            {
                struct section* pJumpTableSection = NULL;
                pJumpTableSection = (struct section*)getsectbynamefromheader( pHeader, SEG_IMPORT, "__jump_table" );
                if(!pJumpTableSection)
                {
                    pJumpTableSection = (struct section*)getsectbynamefromheader( pHeader, SEG_TEXT, "__symbol_stub" );
                }
                
                if(pJumpTableSection)
                {
                    *pJmpTableOffset = pJumpTableSection->offset;
                    *pJmpTableSize = pJumpTableSection->size;
                }
            }
#endif
            
            return nError;
        }
    }
    return Err_InjectEntry_ImageNotFound;
}


void ReleaseTaskportRight( AuthorizationRef pAuthRef, AuthorizationRights* pTaskRights )
{
    if(pTaskRights)
    {
        AuthorizationFreeItemSet( pTaskRights );
        pTaskRights = NULL;
    }
    
    if(pAuthRef)
    {
        AuthorizationFree( pAuthRef, kAuthorizationFlagDefaults );
    }
}

OSStatus
AcquireTaskportRights()
{
    OSStatus             Status     = noErr;
    AuthorizationRef     pAuthRef   = NULL;
    AuthorizationFlags   nAuthFlags = 0;
    AuthorizationItem    TaskportItem[] = { {"system.privilege.taskport"}, 0, 0, 0 };
    AuthorizationRights  AuthRights     = { 1, TaskportItem };
    AuthorizationRights* pAuthOutRights = NULL;
    
    nAuthFlags = kAuthorizationFlagInteractionAllowed | kAuthorizationFlagExtendRights | kAuthorizationFlagPreAuthorize;
    
    Status = AuthorizationCreate( NULL, kAuthorizationEmptyEnvironment, nAuthFlags, &pAuthRef  );
    if(Status != errAuthorizationSuccess)
    {
        printf(" [%s] Failed to acquire system.privilege.taskport right. Error: %d", __FUNCTION__, (int)Status );
        return Status;
    }
    
    Status = AuthorizationCopyRights( pAuthRef, &AuthRights, kAuthorizationEmptyEnvironment, nAuthFlags, &pAuthOutRights );
    if(Status == errAuthorizationSuccess)
    {
        printf( "[%s] system.privilege.taskport acquired. \n", __FUNCTION__ );
    }
    
    ReleaseTaskportRight( pAuthRef, pAuthOutRights );
    return Status;
}


OSStatus
AcquireTaskportRightsEx()
{
    OSStatus Status;
    AuthorizationRef  pAuthRef = NULL;
    AuthorizationItem TaskportItem[] = { {"system.privilege.taskport.debug"} };
    AuthorizationRights  TaskRights = { 1, TaskportItem };
    AuthorizationRights* pOutTaskRights = NULL;
    AuthorizationFlags   nAuthFlags = 0;

    nAuthFlags = kAuthorizationFlagExtendRights | kAuthorizationFlagPreAuthorize |
                 kAuthorizationFlagInteractionAllowed | (1 << 5) /* kAuthorizationFlagLeastPrivileged */;
    
    Status = AuthorizationCreate( NULL, kAuthorizationEmptyEnvironment, nAuthFlags, &pAuthRef );
    if(Status != errAuthorizationSuccess)
    {
        return Status;
    }
    
    /* If you have a window server connection, then this call will put
     up a dialog box if it can.  However, if the current user doesn't
     have a connection to the window server (for instance if they are
     in an ssh session) then this call will return
     errAuthorizationInteractionNotAllowed.
     I want to do this way first, however, since I'd prefer the dialog
     box - for instance if I'm running under Xcode - to trying to prompt.  */
    
    Status = AuthorizationCopyRights( pAuthRef, &TaskRights, kAuthorizationEmptyEnvironment, nAuthFlags, &pOutTaskRights );
    if(Status == errAuthorizationSuccess)
    {
       // printf("[%s] 01 AuthorizationCopyRights Success. \n", __FUNCTION__ );
    }
    else if(Status == errAuthorizationInteractionNotAllowed)
    {
        Status = AcquireTaskportRights_Interact( pAuthRef, TaskRights, nAuthFlags, pOutTaskRights );
    }

    if(Status == errAuthorizationSuccess)
    {
        //printf("[%s] 02 AuthorizationCopyRights Success. \n", __FUNCTION__ );
    }
    else
    {
        printf("[%s] 03 AuthorizationCopyRights Failed. \n", __FUNCTION__ );
    }
    
    ReleaseTaskportRight( pAuthRef, pOutTaskRights );
    return Status;
}


OSStatus
AcquireTaskportRights_Interact(AuthorizationRef  pAuthRef,
                               AuthorizationRights TaskRights,
                               AuthorizationFlags nAuthFlags,
                               AuthorizationRights* pOutTaskRights)
{
    OSStatus Status;
    int   nLength=0;
    char* pczPasswd = NULL;
    char* pczLoginName = NULL;
    char  czInput[MAX_PATH];
    
    /* Okay, so the straight call couldn't query, so we're going to
     have to get the username & password and send them by hand to AuthorizationCopyRights.  */
    
    memset( czInput, 0, sizeof(czInput) );
    pczLoginName = getlogin();
    if(!pczLoginName)
    {
        return errAuthorizationInvalidPointer;
    }
    
    printf("We need authorization from an admin user to run the debugger.\n");
    printf("This will only happen once per login session.\n");
    printf("Admin username (%s): ", pczLoginName );
    
    
    fgets( czInput, MAX_PATH, stdin );
    if(czInput[0] != '\n')
    {
        nLength = (int)strlen(czInput);
        czInput[ nLength-1 ] = '\0';
        pczLoginName = czInput;
    }
    
    pczPasswd = getpass("passwd:");
    if(!pczPasswd)
    {
        return errAuthorizationInvalidPointer;
    }
    
    AuthorizationItem AuthItems[] =
    {
        { kAuthorizationEnvironmentUsername },
        { kAuthorizationEnvironmentPassword },
        { kAuthorizationEnvironmentShared   }
    };
    
    AuthorizationEnvironment Env = { 3, AuthItems };
    AuthItems[0].valueLength = strlen( pczLoginName );
    AuthItems[0].value       = pczLoginName;
    AuthItems[1].valueLength = strlen( pczPasswd );
    AuthItems[1].value       = pczPasswd;
    
    /* If we got rights in the AuthorizationCopyRights call above,
     free it before we reuse the pointer. */
    
    if(pOutTaskRights != NULL)
    {
        AuthorizationFreeItemSet( pOutTaskRights );
        pOutTaskRights = NULL;
    }
    Status = AuthorizationCopyRights( pAuthRef, &TaskRights, &Env, nAuthFlags, &pOutTaskRights );
    return Status;
}

#include <mach/task.h>
#include <mach/task_special_ports.h>


mach_error_t
MachInject(mach_inject_entry pThreadEntry, void* pParamBlock, size_t nParamSize, pid_t nPID, vm_size_t nStackSize)
{
    
    ULONG        nJumpOffset  = 0;
    ULONG        nJumpSize    = 0;
    ULONG        nImageSize   = 0;
    mach_port_t  pRemoteTask   = 0;
    vm_address_t pRemoteStack  = 0;
    vm_address_t pRemoteCode   = 0;
    thread_act_t pRemoteThread = 0;
    mach_error_t nError = 0;
    void*        pMachImage    = NULL;
    
    if(nStackSize == 0)
    {
        nStackSize = 16*1024;
    }

    nError = FetchMachImage( (void*)pThreadEntry, &pMachImage, &nImageSize, &nJumpOffset, &nJumpSize );
    if(0 != nError) return nError;
    
    AcquireTaskportRightsEx();
    nError = task_for_pid( mach_task_self(), nPID, &pRemoteTask );
    
#if defined(__i386__) || defined(__x86_64__)
    if(5 == nError)
    {
        printf("[%s] Could not access task for pid %d. You probably need to add user to procmod group\n", __FUNCTION__, nPID );
    }
#endif

    printf("[%s] Task=%d, Task=%x \n", __FUNCTION__, pRemoteTask, pRemoteTask );
    
    if(!nError)
    {
        nError = vm_allocate( pRemoteTask, &pRemoteStack, nStackSize, 1 );
        if(!nError)
        {
            nError = vm_protect( pRemoteTask, pRemoteStack, nStackSize, 0, VM_PROT_READ | VM_PROT_WRITE );
        }
    }
    
    if(!nError)
    {
        nError = vm_allocate( pRemoteTask, &pRemoteCode, (vm_size_t)nImageSize, 1 );
        if(!nError)
        {
            nError = vm_protect( pRemoteTask, pRemoteCode, (vm_size_t)nImageSize, 0, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE );
        }
    }
    
    if(!nError)
    {
#if defined (__i386__)

        void*  pNewFixedImage = NULL;
        ptrdiff_t nFixedOffset = 0;
        // on x86, jump table use relative jump instructions (jmp), which means the offset needs to be corrected.
        // We thus copy the image and fix the offset by hand.
        nFixedOffset = (ptrdiff_t)((ULONG)pMachImage - pRemoteCode);
        
        pNewFixedImage = FetchUpdateNewImage( pMachImage, nImageSize, nJumpOffset, nJumpSize, nFixedOffset );
        if(pNewFixedImage)
        {
            nError = vm_write( pRemoteTask, pRemoteCode, (pointer_t)pNewFixedImage, (mach_msg_type_number_t)nImageSize );
            free( pNewFixedImage );
        }
        
#elif defined (__x86_64__)
        nError = vm_write( pRemoteTask, pRemoteCode, (pointer_t)pMachImage, (unsigned int)nImageSize );
#endif
    }
    
    vm_address_t pRemoteParamBlock = 0;
    if(!nError && pParamBlock != NULL && nParamSize)
    {
        nError = vm_allocate( pRemoteTask, &pRemoteParamBlock, nParamSize, 1 );
        if(!nError)
        {
            nError = vm_write( pRemoteTask, pRemoteParamBlock, (pointer_t)pParamBlock, (unsigned int)nParamSize );
            printf("[%s] Wrote RemoteParamBlock with size=%ld \n", __FUNCTION__, nParamSize );
        }
    }
    
    ptrdiff_t ThreadEntryOffset = 0;
    ptrdiff_t ImageOffset       = 0;
    if(!nError)
    {
        void* pPos=NULL;
        pPos = (void*)pThreadEntry;
        pPos = (void*)((ULONG)pPos - (ULONG)pMachImage);
        ThreadEntryOffset = (ptrdiff_t)pPos;
        
#if defined (__i386__)
        ImageOffset = 0;
#elif defined (__x86_64__)
        ImageOffset = 0;
#endif
    }
    
    //
    // RemoteThread
    //
    
#if defined (__i386__)
    
    #define PARAM_COUNT 4
    #define STACK_CONTENTS_SIZE ((1+PARAM_COUNT)*sizeof(unsigned int))
    
    if(!nError)
    {
        // 1 for the return address and 1 for each param
        // first entry is return address (see above *)
        unsigned int         StackContents[1+PARAM_COUNT];
        vm_address_t         pDummyStack = NULL;
        x86_thread_state32_t RemoteThreadState;
        memset( &RemoteThreadState, 0, sizeof(RemoteThreadState) );
    
        pDummyStack = pRemoteStack;
        pRemoteStack += (nStackSize/2);
        pRemoteStack -= 4;
        
        StackContents[0] = 0xDEADBEEF; // Invalid return assress
        StackContents[1] = ImageOffset;
        StackContents[2] = pRemoteParamBlock;
        StackContents[3] = nParamSize;
        StackContents[4] = pDummyStack;
        // We use the remote stack we allocated as the fake thread struct.
        // We should probably use a dedicated memory zone.
        // We don't fill it with 0, vm_allocate did it for us
        
        // push StackContents
        nError = vm_write( pRemoteTask, pRemoteStack, (pointer_t)StackContents, STACK_CONTENTS_SIZE );
        
        // Set Remote Program Counter
        RemoteThreadState.__eip = (unsigned int)(pRemoteCode);
        RemoteThreadState.__eip += ThreadEntryOffset;
        // Set Remote Stack Pointer
        RemoteThreadState.__esp = (unsigned int)(pRemoteStack);
        
        // Create Thread and launch it
        nError = thread_create_running( pRemoteTask,
                                        i386_THREAD_STATE, (thread_state_t)&RemoteThreadState,
                                        i386_THREAD_STATE_COUNT, &pRemoteThread );
        if(nError)
        {
            printf("[%s] thread_create_running Failed. Error=%d \n", __FUNCTION__, nError );
        }
    }
    
#elif defined (__x86_64__)
    
    #define PARAM_COUNT64 0
    #define STACK_CONTENTS_SIZE64 ((1+PARAM_COUNT64)*sizeof(unsigned long long))
    
    if(!nError)
    {
        unsigned long long   StackContents64[1+PARAM_COUNT64];
        vm_address_t         pDummyStack = NULL;
        x86_thread_state64_t RemoteThreadState64;
        memset( &RemoteThreadState64, 0, sizeof(RemoteThreadState64) );
    
        pDummyStack = pRemoteStack;
        pRemoteStack += (nStackSize/2);
        pRemoteStack -= 4; // Whie 4 --> 8
        
        // 1 for the return address and 1 for each param
        // first entry is return address (see above *)
        StackContents64[0] = 0x00000DEADBEA7DAD; // invalid return address
        
        // push StackContents
        nError = vm_write( pRemoteTask, pRemoteStack, (pointer_t)StackContents64, STACK_CONTENTS_SIZE64 );
        
        RemoteThreadState64.__rdi = (unsigned long long)(ImageOffset);
        RemoteThreadState64.__rsi = (unsigned long long)(pRemoteParamBlock);
        RemoteThreadState64.__rdx = (unsigned long long)(nParamSize);
        RemoteThreadState64.__rcx = (unsigned long long)(pDummyStack);
        
        // Set Remote Program Counter
        RemoteThreadState64.__rip = (unsigned long long)(pRemoteCode);
        RemoteThreadState64.__rip += ThreadEntryOffset;
        // Set remote Stack Pointer
        RemoteThreadState64.__rsp = (unsigned long long)(pRemoteStack);
        
        // create thread and launch it
        nError = thread_create_running( pRemoteTask,
                                        x86_THREAD_STATE64, (thread_state_t)&RemoteThreadState64,
                                        x86_THREAD_STATE64_COUNT, &pRemoteThread );
        
        if(nError)
        {
            printf("[%s] thread_create_running Failed. Error=%d \n", __FUNCTION__, nError );
        }
    }
#else
#error architecture not supported
#endif
    
    if(nError)
    {
        printf("[%s] Failed. Error=%d \n", __FUNCTION__, nError );
        if(pRemoteParamBlock) vm_deallocate( pRemoteTask, pRemoteParamBlock, (size_t)nParamSize );
        if(pRemoteCode) vm_deallocate( pRemoteTask, pRemoteCode, (size_t)nImageSize );
        if(pRemoteStack) vm_deallocate( pRemoteTask, pRemoteStack, (size_t)nStackSize );
        return nError;
    }
    
    printf("[%s] Success. \n", __FUNCTION__ );
    return nError;
}


#if defined (__i386__)

void*
FetchUpdateNewImage( const void* pMachImage,
                     ULONG       nImageSize,
                     ULONG       nJumpOffset,
                     ULONG       nJumpSize,
                     ptrdiff_t   nFixedOffset )
{
    ULONG nIndex         = 0;
    ULONG nJumpCount     = 0;
    PBYTE pbJumpValue    = NULL;
    void* pJumpTable     = NULL;
    void* pNewFixedImage = NULL;
    
    pNewFixedImage = (void*)malloc( (size_t)nImageSize );
    if(!pNewFixedImage) return NULL;
    
    bzero( pNewFixedImage, (size_t)nImageSize );
    bcopy( pMachImage, pNewFixedImage, (size_t)nImageSize );
    
    pJumpTable = (void*)((ULONG)pNewFixedImage + nJumpOffset);
    if(!pJumpTable)
    {
        free( pNewFixedImage );
        return NULL;
    }
    
    // relative jump          --> 0xEB cb,           --> jump short
    //                            0xE9 cw, 0xE9 cd   --> jump near
    // absolute indirect jump --> 0xFF /4 cw, 0xFF /4 cd, 0xFF /4 cq,
    //                            0xFF /5 cw, 0xFF /5 cd, REX.W 0xFF /5 cq
    // absolute jump          --> 0xEA cd, 0xEA cq
    
    // Absolute Indirect jump table
    if(*(unsigned char*)pJumpTable == 0xFF)
    {
        nJumpCount = nJumpSize / 6;
        for(nIndex=0; nIndex<nJumpCount; nIndex++)
        {   // skip 0xff xx
            pJumpTable = (void*)((int)pJumpTable + 2);
            pbJumpValue = *((BYTE**)pJumpTable);
            fprintf( stderr, "At %p --> Updating %p to %p \n", (char*)pJumpTable-2, pbJumpValue, pbJumpValue - nFixedOffset );
            
            pbJumpValue -= nFixedOffset;
            *((BYTE **)pJumpTable) = pbJumpValue;
            pJumpTable = (void*)((int)pJumpTable + 4);
        }
    }
    else
    {
        nJumpCount = nJumpSize / 5;
        pJumpTable = (void*)((int)pJumpTable+1);
        for(nIndex=0; nIndex<nJumpCount; nIndex++)
        {
            unsigned int JmpValue = *((unsigned int*)pJumpTable);
            JmpValue += nFixedOffset;
            *((unsigned int*)pJumpTable) = JmpValue;
            pJumpTable = (void*)((int)pJumpTable+5);
        }
    }
    return pNewFixedImage;
}

#endif









































