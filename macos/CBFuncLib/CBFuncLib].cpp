
#include <cstdio>
#include <cstring>
#include <mach/mach.h>
#include <mach/thread_act.h>
#include <mach/mach_init.h>
#include <pthread.h>
#include <dlfcn.h>
#include <signal.h>
#include <sys/proc_info.h>
#include <libproc.h>
#include <sys/types.h>
#include <mach/error.h>
#include <mach/vm_types.h>
#include <stddef.h>
#include <iostream>

#define DLLEXPORT __attribute__((visibility("default")))

void*  RemoteThreadProc( void* pParam );
extern "C" void __pthread_set_self(void*);

extern "C" void InstallHook( ptrdiff_t offset, void* pParam, size_t pSize, void* pDummy) DLLEXPORT;

void*
RemoteThreadProc(void* pParam)
{
    void* pHandle = NULL;
    
    if(!pParam) return NULL;
    
    pHandle = dlopen( (char*)pParam, RTLD_NOW );
    if(!pHandle)
    {
        printf("Could not load patch bundle: %s\n", dlerror());
        fprintf(stderr, "Could not load patch bundle: %s\n", dlerror());
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



