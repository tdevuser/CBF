
#include "CBFInject.h"

#include <cstdio>
#include <cstring>
#include <mach/mach.h>
#include <mach/mach_init.h>
#include <mach/thread_act.h>
#include <mach/machine.h>
#include <pthread.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <libproc.h>
#include <sys/sysctl.h>
#include <sys/proc_info.h>
#include <mach/machine.h>
#include <mach-o/dyld.h>
#include "MachInject.h"


CBFInject g_Inject;

typedef bool (*PFSHookInstall)(pid_t nPID);


CBFInject::~CBFInject()
{
    if(m_pInjectHandle)
    {
        dlclose( m_pInjectHandle );
        m_pInjectHandle = NULL;
    }
}

CBFInject::CBFInject()
: m_nCpuType(0), m_pInjectHandle(NULL), m_pInjectProc(NULL), m_pHookAPIHandle(NULL)
{
    FetchCpuType( getpid(), &m_nCpuType );
 
    if(m_nCpuType == CPU_TYPE_X86_64)
    {
        printf("[%s] uid=%d, pid=%d, proc=%s, 64bit \n", __FUNCTION__, getuid(), getpid(), getprogname());
    }
    else if(m_nCpuType == CPU_TYPE_X86)
    {
        printf("[%s] uid=%d, pid=%d, proc=%s, 32bit \n", __FUNCTION__, getuid(), getpid(), getprogname());
    }
    
    m_pInjectHandle = dlopen( CBF_LIB, RTLD_NOW | RTLD_LOCAL );
    if(!m_pInjectHandle)
    {
        printf("[%s] dlopen error=%s \n", __FUNCTION__, dlerror() );
        return;
    }
    
    m_pInjectProc = dlsym( m_pInjectHandle, FN_INSTALLHOOK );
    if(!m_pInjectProc)
    {
        printf("[%s] InstallHook == null \n", __FUNCTION__ );
        return;
    }
    printf("[%s] InstallHook=0x%p \n", __FUNCTION__, m_pInjectProc );
    
}


#define EXCEPT_PROCESS "kernel_task;launchd;PIProtector"

bool CBFInject::InjectAll(const char* pczLibName)
{
    bool  bSuc = false;
    cpu_type_t nCpuType = 0;
    int   nMaxProc=0, nLength=0, nPos=0;
    pid_t PIDArray[ 2048 ], nCurPid=0;
    char  czCurPath[ PROC_PIDPATHINFO_MAXSIZE ];
    char  czCurName[ PROC_PIDPATHINFO_MAXSIZE ];
    
    nMaxProc = proc_listpids( PROC_ALL_PIDS, 0, NULL, 0 );
    
    memset( &PIDArray, 0, sizeof(PIDArray) );
    proc_listpids( PROC_ALL_PIDS, 0, PIDArray, sizeof(PIDArray) );
    for(int i=0; i<nMaxProc; i++)
    {
        nCurPid = PIDArray[i];
        if(nCurPid <= 1) continue;
    
        memset( czCurPath, 0, sizeof(czCurPath) );
        proc_pidpath( nCurPid, czCurPath, sizeof(czCurPath) );
        nLength = (int)strlen( czCurPath );
        if(nLength <= 0) continue;

        nPos = nLength;
        while(nPos && czCurPath[ nPos ] != '/') { --nPos; }
        
        memset( czCurName, 0, sizeof(czCurName) );
        strcpy( czCurName, czCurPath+ nPos + 1);
        
        if( strstr(EXCEPT_PROCESS, czCurName) ||
            !strncasecmp( czCurName, getprogname(), strlen(getprogname()) ))
        {
            continue;
        }
    
        bSuc = FetchCpuType( nCurPid, &nCpuType );
        if(!bSuc || GetCpuType() != nCpuType)
        {
            printf("Inject Skipped. pid=%d, proc=%s, CpuType=%08x \n", nCurPid, czCurName, nCpuType );
            continue;
        }
        
        bSuc = Inject( nCurPid, pczLibName );
        if(bSuc)
        {
            printf("Inject Succes. pid=%d, proc=%s, CpuType=%08x \n", nCurPid, czCurName, nCpuType );
        }
        else
        {
             printf("Inject Failed. pid=%d, proc=%s, CpuType=%08x \n", nCurPid, czCurName, nCpuType );
        }
    }
    return true;
}


bool CBFInject::Inject(pid_t nInjPid, const char* pczLibName)
{
    size_t       nLength = 0;
    mach_error_t nError  = 0;
    
    if(!m_pInjectHandle || !m_pInjectProc || !pczLibName)
    {
        return false;
    }
    
    nLength = strlen( pczLibName )+1;    
    nError = MachInject( (mach_inject_entry)m_pInjectProc, (void*)pczLibName, nLength, nInjPid, 0 );
    if(nError != 0)
    {
        printf("[%s] MachInject=%d \n", __FUNCTION__, nError );
        return false;
    }
    return true;
}


pid_t CBFInject::GetProcessID(const char* pczProcName)
{
    int   nMaxProc=0, nLength=0, nPos=0;
    pid_t PIDArray[ 2048 ];
    char  czCurPath[ PROC_PIDPATHINFO_MAXSIZE ];
    char  czCurName[ PROC_PIDPATHINFO_MAXSIZE ];
    
    nMaxProc = proc_listpids( PROC_ALL_PIDS, 0, NULL, 0 );
    
    memset( &PIDArray, 0, sizeof(PIDArray) );
    proc_listpids( PROC_ALL_PIDS, 0, PIDArray, sizeof(PIDArray) );

    for(int i=0; i<nMaxProc; i++)
    {
        if(!PIDArray[i]) continue;
        
        memset( czCurPath, 0, sizeof(czCurPath) );
        proc_pidpath( PIDArray[i], czCurPath, sizeof(czCurPath) );
        
        nLength = (int)strlen(czCurPath );
        if(nLength)
        {
            nPos = nLength;
            
            while(nPos && czCurPath[ nPos ] != '/')
                --nPos;
            
            strcpy( czCurName, czCurPath+ nPos + 1);
            if(!strcmp( czCurName, pczProcName ))
            {
                return PIDArray[i];
            }
        }
    }
    return 0;
}


bool CBFInject::FetchCpuType( pid_t nPID, cpu_type_t* pCpuType )
{
    int nRet=0;
    int Mib[CTL_MAXNAME];
    size_t nPos=0, nLength=0;

    if(!pCpuType)
    {
        return false;
    }
    
    *pCpuType = 0;
    nPos = CTL_MAXNAME;
    nRet = sysctlnametomib( "sysctl.proc_cputype", Mib, &nPos );
    if(nRet != 0)
    {
        return false;
    }
      
    if(nPos > 0)
    {
        nLength = sizeof( *pCpuType );
        Mib[nPos] = nPID;
        nRet = sysctl( Mib, (u_int)nPos+1, pCpuType, &nLength, NULL, 0 );
        if(nRet == 0)
        {
            return true;
        }
    }
    return false;
}


bool CBFInject::HookLibLoad(const char* pczLibName)
{
    /*
    bool  bSuc = false;
    PFSHookInstall pSHookInstall = NULL;
    pid_t nPID = 0;
    */
    
    m_pHookAPIHandle = dlopen( pczLibName,  RTLD_NOW );
    if(!m_pHookAPIHandle)
    {
        return false;
    }
    
    /*
    pSHookInstall = (PFSHookInstall)dlsym( m_pHookAPIHandle, "SHook_Install" );
    if(pSHookInstall)
    {
        nPID = getpid();
        bSuc = pSHookInstall( nPID );
        return bSuc;
    }
     */
    
    return true;
}


bool CBFInject::HookLibUnload()
{
    if(!m_pHookAPIHandle)
    {
        return false;
    }

    dlclose( m_pHookAPIHandle );
    m_pHookAPIHandle = NULL;
    return true;
}


















