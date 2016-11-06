
#ifndef _MACH_FMT_H_
#define _MACH_FMT_H_

#include <stdint.h>
#include <fcntl.h>


#ifdef __cplusplus
extern "C"
{
#endif


class CMachHook
{
public:
    CMachHook();
    ~CMachHook();
    
public:
    void* MachHook_Init();
    void  MachHook_Free();
    
public:
    void* MachHook_Func(void* pHandle, char* pczFuncName);
    
public:
    void* ReadFile( int fd, size_t nOffset, size_t nCount );
    uint32_t ReadHeaderOffset(int nDesc);
    
};

    
    
    
#ifdef __cplusplus
}
#endif

#endif
