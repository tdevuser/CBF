
#ifndef _CBF_INJECT_H_
#define _CBF_INJECT_H_

#include <sys/types.h>
#include <mach/machine.h>

#define CBF_LIB "CBFuncLib.dylib"
#define CBF_API "CBFuncAPI.dylib"
#define FN_INSTALLHOOK "InstallHook"


class CBFInject
{
public:
    CBFInject();
    ~CBFInject();

public:
    bool InjectAll(const char* pczLibName);
    bool Inject(pid_t pid, const char* pczLibName);
    
    bool HookLibLoad(const char* pczLibName);
    bool HookLibUnload(void);
    
public:
    pid_t GetProcessID(const char* pczProcName);
    bool FetchCpuType( pid_t pid, cpu_type_t* pCpuType );
    cpu_type_t GetCpuType() { return m_nCpuType; }
    
private:
    cpu_type_t m_nCpuType;
    void* m_pInjectProc;
    void* m_pInjectHandle;
    void* m_pHookAPIHandle;
    
};


extern CBFInject g_Inject;


#endif   // _CBF_INJECT_H_
