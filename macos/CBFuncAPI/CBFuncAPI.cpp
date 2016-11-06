
#include "CBFuncAPI.h"
#include "CodeSect.h"
#include "HookDefMain.h"
#include "HookCode.h"
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <libproc.h>
#include <cups/cups.h>


#define LOG_PATH_PVI      "/usr/local/log/"
#define HOOKAPI_WRITE_LOG "hook.log"

#define LIB_SYSTEM "libSystem.B.dylib"
#define LIB_CUPS   "libcups.dylib"


CBFuncAPI  g_PIApi;


bool SHook_Init()
{
    return g_PIApi.Init();
}

bool SHook_Uninit()
{
    return g_PIApi.Uninit();
}

bool SHook_Install(pid_t nPID)
{
    return g_PIApi.Install(nPID);
}

bool SHook_Uninstall()
{
    return g_PIApi.Uninstall();
}

CBFuncAPI::CBFuncAPI() : m_nPID(-1), m_bInit(false)
{
    memset( m_czLogPath, 0, sizeof(m_czLogPath) );
}

CBFuncAPI::~CBFuncAPI()
{
}

pid_t CBFuncAPI::GetProcessID(const char* pczProcName)
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


bool CBFuncAPI::Init()
{
    bool  bSuc = false;
    pid_t nPID = 0;
    char  czProcPath[MAX_PATH];
    
    g_PIApi.WriteLogApp( false, "\n\n\n" );
    
    g_PIApi.SetLogPath();
   
    memset( czProcPath, 0, sizeof(czProcPath) );
    GetProcessPath( getpid(), czProcPath, sizeof(czProcPath) );
    
    g_PIApi.WriteLogApp( true, "[%s] ProcessID    = %d \n", __FUNCTION__, getpid() );
    g_PIApi.WriteLogApp( true, "[%s] ProcessName  = %s \n", __FUNCTION__, getprogname() );
    g_PIApi.WriteLogApp( true, "[%s] ProccessPath = %s \n", __FUNCTION__, czProcPath );
    g_PIApi.WriteLogApp( true, "[%s] LogPath = %s \n", __FUNCTION__, m_czLogPath );
    g_PIApi.WriteLogApp( false, "\n" );
    
    g_Hook.Initialize();
    
    bSuc = Install( nPID );
    if(!bSuc)
    {
        g_PIApi.WriteLogApp( true, "[%s] pid=%d, proc=%s Called. \n", __FUNCTION__, getpid(), getprogname() );
        return bSuc;
    }

    g_PIApi.WriteLogApp( false, "\n" );
    g_PIApi.WriteLogApp( true, "[%s] pid=%d, proc=%s Called. \n", __FUNCTION__, getpid(), getprogname() );
    g_PIApi.WriteLogApp( false, "\n" );
    return true;
}

bool CBFuncAPI::Uninit()
{
    bool bSuc = false;
    
    g_PIApi.WriteLogApp( true, "[%s] Called. \n", __FUNCTION__ );

    bSuc = Uninstall();
    bSuc = g_Hook.Finalize();
    return bSuc;
}

bool CBFuncAPI::Install(pid_t nPID)
{
    bool bSuc = false;
    
    if(true == m_bInit)
    {
        g_PIApi.WriteLogApp( true, "[%s] Already Init Failed. \n", __FUNCTION__ );
        return true;
    }
    
    bSuc = g_PIApi.HookAPI_Calls();
    if(!bSuc)
    {
        g_PIApi.WriteLogApp( true, "[%s] HookAPI_Calls Failed. \n", __FUNCTION__ );
        return bSuc;
    }
    m_bInit = true;
    return bSuc;
}

bool CBFuncAPI::Uninstall()
{
    m_bInit = false;
    if(false == g_PIApi.UnhookAPI_Calls())
    {
        printf("[%s] UnhookAPI_Calls Failed. \n", __FUNCTION__ );
        return false;
    }
    return true;
}

bool CBFuncAPI::UnhookAPI_Calls()
{
    
    // CUPS
    if(g_fpnext_cupsGetDests && true == g_Hook.UnhookAPI( (void*)g_fpnext_cupsGetDests ))
    {
        g_fpnext_cupsGetDests = NULL;
    }
    
    if(g_fpnext_cupsFreeDests && true == g_Hook.UnhookAPI( (void*)g_fpnext_cupsFreeDests ))
    {
        g_fpnext_cupsGetDests = NULL;
    }
    
    if(g_fpnext_cupsStartDocument && true == g_Hook.UnhookAPI( (void*)g_fpnext_cupsStartDocument ))
    {
        g_fpnext_cupsStartDocument = NULL;
    }
    
    if(g_fpnext_cupsFinishDocument && true == g_Hook.UnhookAPI( (void*)g_fpnext_cupsFinishDocument ))
    {
        g_fpnext_cupsFinishDocument = NULL;
    }
    
    if(g_fpnext_cupsPrintFile && true == g_Hook.UnhookAPI( (void*)g_fpnext_cupsPrintFile ))
    {
        g_fpnext_cupsPrintFile = NULL;
    }
    
    if(g_fpnext_cupsPrintFile2 && true == g_Hook.UnhookAPI( (void*)g_fpnext_cupsPrintFile2 ))
    {
        g_fpnext_cupsPrintFile2 = NULL;
    }
    
    if(g_fpnext_cupsPrintFiles && true == g_Hook.UnhookAPI( (void*)g_fpnext_cupsPrintFiles ))
    {
        g_fpnext_cupsPrintFiles = NULL;
    }
    
    if(g_fpnext_cupsPrintFiles2 && true == g_Hook.UnhookAPI( (void*)g_fpnext_cupsPrintFiles2 ))
    {
        g_fpnext_cupsPrintFiles2 = NULL;
    }
    
    
    
    
    // Process
    if(g_fpnext_fork && true == g_Hook.UnhookAPI((void*)g_fpnext_fork))
    {
        g_fpnext_fork = NULL;
    }
    
    if(g_fpnext_execl && true == g_Hook.UnhookAPI((void*)g_fpnext_execl))
    {
        g_fpnext_execl = NULL;
    }
    
    if(g_fpnext_execv && true == g_Hook.UnhookAPI((void*)g_fpnext_execv ))
    {
        g_fpnext_execv = NULL;
    }
    
    if(g_fpnext_exit && true == g_Hook.UnhookAPI((void*)g_fpnext_exit ))
    {
        g_fpnext_exit = NULL;
    }
    
    // File
    if(g_fpnext_open && true == g_Hook.UnhookAPI((void*)g_fpnext_open ))
    {
        g_fpnext_open = NULL;
    }
    
    if(g_fpnext_read && true == g_Hook.UnhookAPI((void*)g_fpnext_read))
    {
        g_fpnext_read = NULL;
    }
    
    if(g_fpnext_write && true == g_Hook.UnhookAPI( (void*)g_fpnext_write ))
    {
        g_fpnext_write = NULL;
    }
    
    if(g_fpnext_close && true == g_Hook.UnhookAPI( (void*)g_fpnext_close ))
    {
        g_fpnext_close = NULL;
    }
    return true;
}



bool CBFuncAPI::HookAPI_Calls()
{
    bool  bSuc=false;
    ULONG nSectSize=0;
    
    nSectSize = g_Hook.GetCodeSectLength();
    g_PIApi.WriteLogApp( true, "[%s] GetCodeSectLength() SectSize=%d \n", __FUNCTION__, nSectSize );
    g_PIApi.WriteLogApp( false, "\n" );
    
    // mkdir
    bSuc = g_Hook.HookAPI( LIB_SYSTEM, "_mkdir", (void*)hook_mkdir, (void**)&g_fpnext_mkdir );
    // rmdir
    bSuc = g_Hook.HookAPI( LIB_SYSTEM, "_rmdir", (void*)hook_rmdir, (void**)&g_fpnext_rmdir );
    // mknod
    bSuc = g_Hook.HookAPI( LIB_SYSTEM, "_mknod", (void*)hook_mknod, (void**)&g_fpnext_mknod );
    // remove
    bSuc = g_Hook.HookAPI( LIB_SYSTEM, "_remove", (void*)hook_remove, (void**)&g_fpnext_remove );
    // rename
    bSuc = g_Hook.HookAPI( LIB_SYSTEM, "_rename", (void*)hook_rename, (void**)&g_fpnext_rename );

    // file
    bSuc = g_Hook.HookAPI( LIB_SYSTEM, "_create", (void*)hook_creat, (void**)&g_fpnext_creat );
    bSuc = g_Hook.HookAPI( LIB_SYSTEM, "_open",  (void*)hook_open,  (void**)&g_fpnext_open  );
    bSuc = g_Hook.HookAPI( LIB_SYSTEM, "_read",  (void*)hook_read,  (void**)&g_fpnext_read  );
    bSuc = g_Hook.HookAPI( LIB_SYSTEM, "_write", (void*)hook_write, (void**)&g_fpnext_write );
    bSuc = g_Hook.HookAPI( LIB_SYSTEM, "_close", (void*)hook_close, (void**)&g_fpnext_close );

    // stat
    bSuc = g_Hook.HookAPI( LIB_SYSTEM, "_stat", (void*)hook_stat, (void**)&g_fpnext_stat );
    // fstat
    bSuc = g_Hook.HookAPI( LIB_SYSTEM, "_fstat", (void*)hook_fstat, (void**)&g_fpnext_fstat );
    // lstat
    bSuc = g_Hook.HookAPI( LIB_SYSTEM, "_lstat", (void*)hook_lstat, (void**)&g_fpnext_lstat );
       
    // stat64
    bSuc = g_Hook.HookAPI( LIB_SYSTEM, "_stat64", (void*)hook_stat64, (void**)&g_fpnext_stat64 );
    // fstat64
    bSuc = g_Hook.HookAPI( LIB_SYSTEM, "_fstat64", (void*)hook_fstat64, (void**)&g_fpnext_fstat64 );
    // lstat64
    bSuc = g_Hook.HookAPI( LIB_SYSTEM, "_lstat64", (void*)hook_lstat64, (void**)&g_fpnext_lstat64 );

    // truncate
    bSuc = g_Hook.HookAPI( LIB_SYSTEM, "_truncate", (void*)hook_truncate, (void**)&g_fpnext_truncate );
    // ftruncate
    bSuc = g_Hook.HookAPI( LIB_SYSTEM, "_ftruncate", (void*)hook_ftruncate, (void**)&g_fpnext_ftruncate );
    
    // link
    bSuc = g_Hook.HookAPI( LIB_SYSTEM, "_link", (void*)hook_link, (void**)&g_fpnext_link );
    // unlink
    bSuc = g_Hook.HookAPI( LIB_SYSTEM, "_unlink", (void*)hook_unlink, (void**)&g_fpnext_unlink );
    // symlink
    bSuc = g_Hook.HookAPI( LIB_SYSTEM, "_symlink", (void*)hook_symlink, (void**)&g_fpnext_symlink );
    
    // mmap
    bSuc = g_Hook.HookAPI( LIB_SYSTEM, "_mmap", (void*)hook_mmap, (void**)&g_fpnext_mmap );
    // munmap
    bSuc = g_Hook.HookAPI( LIB_SYSTEM, "_munmap", (void*)hook_munmap, (void**)&g_fpnext_munmap );
    
    // ioctl
    bSuc = g_Hook.HookAPI( LIB_SYSTEM, "_ioctl", (void*)hook_ioctl, (void**)&g_fpnext_ioctl );
    // fcntl
    bSuc = g_Hook.HookAPI( LIB_SYSTEM, "_fcntl", (void*)hook_fcntl, (void**)&g_fpnext_fcntl );

    // socket
    bSuc = g_Hook.HookAPI( LIB_SYSTEM, "_socket", (void*)hook_socket, (void**)&g_fpnext_socket );
    // connect
    bSuc = g_Hook.HookAPI( LIB_SYSTEM, "_connect", (void*)hook_connect, (void**)&g_fpnext_connect );
    
    // send
    bSuc = g_Hook.HookAPI( LIB_SYSTEM, "_send", (void*)hook_send, (void**)&g_fpnext_send );
    // sendto
    bSuc = g_Hook.HookAPI( LIB_SYSTEM, "_sendto", (void*)hook_sendto, (void**)&g_fpnext_sendto );
    // sendmsg
    bSuc = g_Hook.HookAPI( LIB_SYSTEM, "_sendmsg", (void*)hook_sendmsg, (void**)&g_fpnext_sendmsg );

    // recv
    bSuc = g_Hook.HookAPI( LIB_SYSTEM, "_recv", (void*)hook_recv, (void**)&g_fpnext_recv );
    // recvfrom
    bSuc = g_Hook.HookAPI( LIB_SYSTEM, "_recvfrom", (void*)hook_recvfrom, (void**)&g_fpnext_recvfrom );
    // recvmsg
    bSuc = g_Hook.HookAPI( LIB_SYSTEM, "_recvmsg", (void*)hook_recvmsg, (void**)&g_fpnext_recvmsg );

    // proc
    bSuc = g_Hook.HookAPI( LIB_SYSTEM, "_fork",  (void*)hook_fork,  (void**)&g_fpnext_fork  );
    bSuc = g_Hook.HookAPI( LIB_SYSTEM, "_execl", (void*)hook_execl, (void**)&g_fpnext_execl );
    bSuc = g_Hook.HookAPI( LIB_SYSTEM, "_execv", (void*)hook_execv, (void**)&g_fpnext_execv );
    bSuc = g_Hook.HookAPI( LIB_SYSTEM, "_exit",  (void*)hook_exit,  (void**)&g_fpnext_exit  );
    
    // cups
    bSuc = g_Hook.HookAPI( LIB_CUPS, "_cupsGetDests",  (void*)hook_cupsGetDests, (void**)&g_fpnext_cupsGetDests );
    bSuc = g_Hook.HookAPI( LIB_CUPS, "_cupsFreeDests", (void*)hook_cupsFreeDests, (void**)&g_fpnext_cupsFreeDests );
    bSuc = g_Hook.HookAPI( LIB_CUPS, "_cupsStartDocument", (void*)hook_cupsStartDocument, (void**)&g_fpnext_cupsStartDocument );
    bSuc = g_Hook.HookAPI( LIB_CUPS, "_cupsFinishDocument",(void*)hook_cupsFinishDocument, (void**)&g_fpnext_cupsFinishDocument );
    bSuc = g_Hook.HookAPI( LIB_CUPS, "_cupsPrintFile",  (void*)hook_cupsPrintFile, (void**)&g_fpnext_cupsPrintFile );
    bSuc = g_Hook.HookAPI( LIB_CUPS, "_cupsPrintFile2", (void*)hook_cupsPrintFile2, (void**)&g_fpnext_cupsPrintFile2 );
    bSuc = g_Hook.HookAPI( LIB_CUPS, "_cupsPrintFiles", (void*)hook_cupsPrintFiles, (void**)&g_fpnext_cupsPrintFiles );
    bSuc = g_Hook.HookAPI( LIB_CUPS, "_cupsPrintFiles2",(void*)hook_cupsPrintFiles2,(void**)&g_fpnext_cupsPrintFiles2 );
    
    return bSuc;
}



/*
bool CBFuncAPI::HookAPI_Code_Calls()
{
    bool bSuc = false;
    int  nSizeCode = 0;
    //
    g_fpnext_rand = next_rand;
    nSizeCode = (int)((ULONG)hook_rand - (ULONG)g_fpnext_rand);
    bSuc = g_Hook.HookAPI_Code( LIB_SYSTEM, "_rand", (void*)hook_rand, (void*)g_fpnext_rand, nSizeCode );
    //
    g_fpnext_open = next_open;
    nSizeCode = (int)((ULONG)hook_open - (ULONG)g_fpnext_open);
    bSuc = g_Hook.HookAPI_Code( LIB_SYSTEM, "_open", (void*)hook_open, (void*)g_fpnext_open, nSizeCode );
    
    g_fpnext_read = next_read;
    nSizeCode = (int)((ULONG)hook_read - (ULONG)g_fpnext_read);
    bSuc = g_Hook.HookAPI_Code( LIB_SYSTEM, "_read", (void*)hook_read, (void*)g_fpnext_read, nSizeCode );
    
    g_fpnext_write = next_write;
    nSizeCode = (int)((ULONG)hook_write - (ULONG)g_fpnext_write);
    bSuc = g_Hook.HookAPI_Code( LIB_SYSTEM, "_write", (void*)hook_write, (void*)g_fpnext_write, nSizeCode );
    
    g_fpnext_close = next_close;
    nSizeCode = (int)((ULONG)hook_close - (ULONG)g_fpnext_close);
    bSuc = g_Hook.HookAPI_Code( LIB_SYSTEM, "_close", (void*)hook_close, (void*)g_fpnext_close, nSizeCode );
    return bSuc;
}
*/



bool CBFuncAPI::SetLogPath()
{
    memset( m_czLogPath, 0, sizeof(m_czLogPath) );
    strcpy( m_czLogPath, LOG_PATH_PVI );
    
    mkdir( m_czLogPath, 0755 );
    return true;
}

bool CBFuncAPI::SetLogPath(pid_t nPID)
{
    bool bSuc = false;
    char czProcPath[PROC_PIDPATHINFO_MAXSIZE];
    char* pczPos = NULL;
    
    m_nPID = nPID;
    memset( czProcPath, 0, sizeof(czProcPath) );
    bSuc = GetProcessPath( nPID, czProcPath, sizeof(czProcPath) );
    if(!bSuc)
    {
        g_PIApi.WriteLogApp( true, "[%s] error. pid=%d \n", __FUNCTION__, nPID );
        return false;
    }
    
    strcpy( m_czLogPath, czProcPath );
    pczPos = strrchr( m_czLogPath, '/' );
    if( pczPos++ )
    {
        *pczPos = '\0';
    }
    g_PIApi.WriteLogApp( true, "[%s] pid=%d, procpath=%s \n", __FUNCTION__, nPID, m_czLogPath );
    g_PIApi.WriteLogApp( false, "\n\n" );
    g_PIApi.WriteLogHookAPI( __FUNCTION__, "" );
    g_PIApi.WriteLogApp( false, "\n\n" );
    return bSuc;
}

bool CBFuncAPI::GetProcessPath( pid_t nPID, char* pczOutPath, uint32_t nMaxOutPath )
{
    int    nRet = 0;
    size_t nLength = 0;
    char   czProcPath[PROC_PIDPATHINFO_MAXSIZE];
    
    memset( czProcPath, 0, sizeof(czProcPath) );
    nRet = proc_pidpath( nPID, czProcPath, sizeof(czProcPath) );
    if(nRet <= 0)
    {
        g_PIApi.WriteLogApp( true, "[%s] pid=%d, err=%d, err-msg=%s \n", __FUNCTION__, nPID, errno, strerror(errno) );
        return false;
    }
    
    nLength = MIN( strlen(czProcPath), nMaxOutPath );
    strncpy( pczOutPath, czProcPath, nLength );
    
    g_PIApi.WriteLogApp( true, "[%s] ProcessId=%d, ProcessPath=%s \n", __FUNCTION__, nPID, czProcPath );
    return true;
}

void CBFuncAPI::GetLogDateTime(char* pczCurTime, int nTimeBufSize)
{
    time_t     CurTime;
    struct tm* pTimeData = NULL;
    
    if(!pczCurTime) return;
    
    time( &CurTime );
    pTimeData = localtime( &CurTime );
    if(!pTimeData) return;
    
    snprintf(pczCurTime, nTimeBufSize, "%04d%02d%02d-%02d%02d%02d",
             pTimeData->tm_year+1900, pTimeData->tm_mon+1, pTimeData->tm_mday,
             pTimeData->tm_hour, pTimeData->tm_min, pTimeData->tm_sec  );
    
}
                 
void CBFuncAPI::GetLogDate(char* pczCurDate, int nMaxCurDate )
{
    time_t     CurTime;
    struct tm* pTimeData = NULL;
    
    if(!pczCurDate) return;
    
    time( &CurTime );
    pTimeData = localtime( &CurTime );
    if(!pTimeData) return;
    
    snprintf(pczCurDate, nMaxCurDate, "%04d%02d%02d",
             pTimeData->tm_year+1900, pTimeData->tm_mon+1, pTimeData->tm_mday );
             
}

void CBFuncAPI::WriteLog(char* pczBuf)
{
    FILE* pFp = NULL;
    char  czLogDate[MAX_TIME];
    char  czCurPath[MAX_PATH];
    pid_t nPID = 0;
    
    if(!pczBuf) return;
    
    nPID = getpid();
    memset( czLogDate, 0, sizeof(czLogDate) );
    GetLogDate( czLogDate, sizeof(czLogDate) );
    
    memset( czCurPath, 0, sizeof(czCurPath) );
    snprintf( czCurPath, sizeof(czCurPath), "%s%s_%s", m_czLogPath, czLogDate, HOOKAPI_WRITE_LOG );
    
    pFp = fopen( czCurPath, "a+" );
    if(pFp)
    {
        fprintf( pFp, "%s", pczBuf );
        fclose( pFp );
    }
}

void CBFuncAPI::WriteLogApp(bool bDate, const char* pFmt, ...)
{
    char czTime[MAX_TIME];
    char czFmtBuf[MAX_PATH];
    char czPrtBuf[MAX_BUF_1K];
    
    if(!pFmt) return;
    
    memset( czTime,   0, sizeof(czTime)   );
    memset( czFmtBuf, 0, sizeof(czFmtBuf) );
    memset( czPrtBuf, 0, sizeof(czPrtBuf) );
    
    va_list vArg;
    va_start( vArg, pFmt );
    vsnprintf( czFmtBuf, sizeof(czFmtBuf), pFmt, vArg );
    va_end(vArg);
    
    GetLogDateTime( czTime, sizeof(czTime) );
    
    if(bDate) snprintf( czPrtBuf, sizeof(czPrtBuf), "[%s] %s", czTime, czFmtBuf );
    else      snprintf( czPrtBuf, sizeof(czPrtBuf), "%s", czFmtBuf );

    printf("%s", czPrtBuf );
    
    WriteLog( czPrtBuf );
    
}


void CBFuncAPI::WriteLogHookAPI(const char* pczFuncName, const char* pFmt, ...)
{
    char czTime[MAX_TIME];
    char czFmtBuf[MAX_PATH];
    char czPrtBuf[MAX_BUF_1K];
    
    if(!pczFuncName || !pFmt) return;
    
    memset( czTime,   0, sizeof(czTime)   );
    memset( czFmtBuf, 0, sizeof(czFmtBuf) );
    memset( czPrtBuf, 0, sizeof(czPrtBuf) );
    
    va_list vArg;
    va_start( vArg, pFmt );
    vsnprintf( czFmtBuf, sizeof(czFmtBuf), pFmt, vArg );
    va_end(vArg);
    
    GetLogDateTime( czTime, sizeof(czTime) );
    
    snprintf( czPrtBuf, sizeof(czPrtBuf), "[%s] %d, %s, %s%s \n",
              czTime, getpid(), getprogname(), pczFuncName, czFmtBuf );
    
    printf("%s", czPrtBuf );
    
    WriteLog( czPrtBuf );
}


void CBFuncAPI::GetBufferFormat(char* pczOutBuf, uint32_t nMaxOutBuf, const char* pFmt, ...)
{
    char czFmtBuf[MAX_PATH];
    
    if(!pczOutBuf || !pFmt) return;
    
    memset( czFmtBuf, 0, sizeof(czFmtBuf) );
    va_list vArg;
    va_start( vArg, pFmt );
    vsnprintf( czFmtBuf, sizeof(czFmtBuf), pFmt, vArg );
    va_end(vArg);
    
    strncpy( pczOutBuf, czFmtBuf, nMaxOutBuf );
}









