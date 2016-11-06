
#ifndef _INJECT_BUNDLE_H_
#define _INJECT_BUNDLE_H_


#ifdef __cplusplus
extern "C"
{
#endif

    

    
    
    
    
    
#ifdef __cplusplus
}
#endif

#endif



/***********************************************************************
 * NAME
 *      inject_bundle -- Inject a dynamic library or bundle into a
 *                       running process
 *
 * SYNOPSIS
 *      inject_bundle path_to_bundle [ pid ]
 *
 * DESCRIPTION
 *      The inject_bundle utility injects a dynamic library or bundle
 *      into another process.  It does this by acquiring access to the
 *      remote process' mach task port (via task_for_pid()) and
 *      creating a new thread to call dlopen().  If the dylib or
 *      bundle exports a function called "run", it will be called
 *      separately.
 *
 * EXIT STATUS
 *      Exits 0 on success, -1 on error.
 **********************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>
#include <err.h>

#include <dlfcn.h>
#include <mach/mach.h>
#include <mach/mach_error.h>
#include <pthread.h>
#include <sys/param.h>


/***********************************************************************
 * Mach Exceptions
 ***********************************************************************/

extern boolean_t exc_server(mach_msg_header_t *request, mach_msg_header_t *reply);

/**********************************************************************
 * Remote task memory
 **********************************************************************/
kern_return_t
remote_copyout(task_t task, void* src, vm_address_t dest, size_t n);

kern_return_t
remote_copyin(task_t task, vm_address_t src, void* dest, size_t n);

extern vm_address_t
remote_malloc(task_t task, size_t size);

extern kern_return_t
remote_free(task_t task, vm_address_t addr);

/**********************************************************************
 * Remote threads
 **********************************************************************/

typedef enum
{
    UNINIT,       // Remote thread not yet initialized (error returned)
    CREATED,      // Thread and remote stack created and allocated
    RUNNING,      // Thread is running
    SUSPENDED,    // Thread suspended, but still allocated
    TERMINATED    // Thread terminated and remote stack deallocated
} remote_thread_state_t;

typedef struct
{
    remote_thread_state_t state;
    task_t                task;
    thread_t              thread;
    vm_address_t          stack;
    size_t                stack_size;
} remote_thread_t;


kern_return_t
create_remote_thread( mach_port_t task, remote_thread_t* rt, vm_address_t start_address, int argc, ... );

kern_return_t
join_remote_thread( remote_thread_t* remote_thread, void** return_value );


/**********************************************************************
 * Bundle injection
 **********************************************************************/

kern_return_t
remote_getpid(task_t task, pid_t* pid);

kern_return_t
inject_bundle( task_t task, const char* bundle_path, void** return_value);

