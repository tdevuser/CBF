
#include "CBFuncExt.h"
#include "CodeSect.h"
#include "HookDefMain.h"
#include "HookCode.h"
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#pragma warning(disable:4819)
#pragma warning(disable:4995)
#pragma warning(disable:4996)

#define LOG_PATH_PVI "/usr/local/log/"
#define HOOKAPI_WRITE_LOG "hook.log"

#define LIB_SYSTEM "libSystem.B.dylib"
#define LIB_CUPS   "libcups.dylib"


CBFuncExt  g_PIApi;


bool SHook_Init()
{
    return g_PIApi.Init();
}
bool SHook_Uninit()
{
    return g_PIApi.Uninit();
}
bool SHook_Install()
{
    return g_PIApi.Install();
}
bool SHook_Uninstall()
{
    return g_PIApi.Uninstall();
}

CBFuncExt::CBFuncExt() : m_nPID(-1), m_bInit(false)
{
    memset( m_czLogPath, 0, sizeof(m_czLogPath) );
}

CBFuncExt::~CBFuncExt()
{
}

DWORD CBFuncExt::GetProcessID(const char* pczProcName)
{
	DWORD dwPID = 0;
    int   nMaxProc=0, nLength=0, nPos=0;
    char  czCurPath[MAX_PATH];
    char  czCurName[MAX_PATH];

	memset( czCurPath, 0, sizeof(czCurPath) );
	memset( czCurName, 0, sizeof(czCurName) );
 
    return 0;
}

DWORD CBFuncExt::GetProcessName(char* pczProcName, int nMaxProcName)
{
	DWORD dwPID = 0;
	DWORD dwRet = 0;

	dwPID = GetCurrentProcessId();

	return dwRet;
}


bool CBFuncExt::Init()
{
    bool  bSuc  = false;
    DWORD dwPID = 0;
	char  czProcName[MAX_PATH];
    char  czProcPath[MAX_PATH];
    
    g_PIApi.WriteLogApp( false, "\n\n\n" );
    
    g_PIApi.SetLogPath();
   
    memset( czProcPath, 0, sizeof(czProcPath) );
    GetProcessPath( GetCurrentProcessId(), czProcPath, sizeof(czProcPath) );
    
    g_PIApi.WriteLogApp( true, "[%s] ProcessID    = %d \n", __FUNCTION__, GetCurrentProcessId() );
	GetProcessName( czProcName, sizeof(czProcName) );
    g_PIApi.WriteLogApp( true, "[%s] ProcessName  = %s \n", __FUNCTION__, czProcName );
    g_PIApi.WriteLogApp( true, "[%s] ProccessPath = %s \n", __FUNCTION__, czProcPath );
    g_PIApi.WriteLogApp( true, "[%s] LogPath = %s \n", __FUNCTION__, m_czLogPath );
    g_PIApi.WriteLogApp( false, "\n" );
    
    g_Hook.Initialize();
    bSuc = Install();
    if(!bSuc)
    {
        g_PIApi.WriteLogApp( true, "[%s] pid=%d Called. \n", __FUNCTION__, GetCurrentProcessId() );
        return bSuc;
    }

    g_PIApi.WriteLogApp( false, "\n" );
    g_PIApi.WriteLogApp( true, "[%s] pid=%d Called. \n", __FUNCTION__, GetCurrentProcessId() );
    g_PIApi.WriteLogApp( false, "\n" );
    return true;
}

bool CBFuncExt::Uninit()
{
    bool bSuc = false;
    
    g_PIApi.WriteLogApp( true, "[%s] Called. \n", __FUNCTION__ );

    bSuc = Uninstall();
    bSuc = g_Hook.Finalize();
    return bSuc;
}

bool CBFuncExt::Install()
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

bool CBFuncExt::Uninstall()
{
    m_bInit = false;
    if(false == g_PIApi.UnhookAPI_Calls())
    {
        printf("[%s] UnhookAPI_Calls Failed. \n", __FUNCTION__ );
        return false;
    }
    return true;
}

bool CBFuncExt::UnhookAPI_Calls()
{
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


bool CBFuncExt::HookAPI_Calls()
{
    bool  bSuc=false;
    ULONG nSectSize=0;
    
    nSectSize = g_Hook.GetCodeSectLength();
    g_PIApi.WriteLogApp( true, "[%s] GetCodeSectLength() SectSize=%d \n", __FUNCTION__, nSectSize );
    
    g_PIApi.WriteLogApp( false, "\n" );

    bSuc = g_Hook.HookAPI( LIB_SYSTEM, "_open",  (void*)hook_open,  (void**)&g_fpnext_open  );
    bSuc = g_Hook.HookAPI( LIB_SYSTEM, "_read",  (void*)hook_read,  (void**)&g_fpnext_read  );
    bSuc = g_Hook.HookAPI( LIB_SYSTEM, "_write", (void*)hook_write, (void**)&g_fpnext_write );
    bSuc = g_Hook.HookAPI( LIB_SYSTEM, "_close", (void*)hook_close, (void**)&g_fpnext_close );

    return bSuc;
}



bool CBFuncExt::SetLogPath()
{
    memset( m_czLogPath, 0, sizeof(m_czLogPath) );
    strcpy( m_czLogPath, LOG_PATH_PVI );
    
	CreateDirectoryA( m_czLogPath, NULL );
    return true;
}

bool CBFuncExt::GetProcessPath( DWORD dwPID, char* pczOutPath, int nMaxOutPath )
{
	int nLength = 0;
	char czProcPath[MAX_PATH];

    memset( czProcPath, 0, sizeof(czProcPath) );
    nLength = min( (int)strlen(czProcPath), nMaxOutPath );
    strncpy( pczOutPath, czProcPath, nLength );
    
    g_PIApi.WriteLogApp( true, "[%s] ProcessId=%d, ProcessPath=%s \n", __FUNCTION__, dwPID, czProcPath );
    return true;
}

void CBFuncExt::GetLogDateTime(char* pczCurTime, int nTimeBufSize)
{
    time_t     CurTime;
    struct tm* pTimeData = NULL;
    
    if(!pczCurTime) return;
    
    time( &CurTime );
    pTimeData = localtime( &CurTime );
    if(!pTimeData) return;
    
    sprintf_s(pczCurTime, nTimeBufSize, "%04d%02d%02d-%02d%02d%02d",
             pTimeData->tm_year+1900, pTimeData->tm_mon+1, pTimeData->tm_mday,
             pTimeData->tm_hour, pTimeData->tm_min, pTimeData->tm_sec  );
    
}
                 
void CBFuncExt::GetLogDate(char* pczCurDate, int nMaxCurDate )
{
    time_t     CurTime;
    struct tm* pTimeData = NULL;
    
    if(!pczCurDate) return;
    
    time( &CurTime );
    pTimeData = localtime( &CurTime );
    if(!pTimeData) return;
    
    sprintf_s(pczCurDate, nMaxCurDate, "%04d%02d%02d",
             pTimeData->tm_year+1900, pTimeData->tm_mon+1, pTimeData->tm_mday );
             
}

void CBFuncExt::WriteLog(char* pczBuf)
{
    FILE* pFp = NULL;
    char czLogDate[MAX_TIME];
    char czCurPath[MAX_PATH];
    int  nPID = 0;
    
    if(!pczBuf) return;
    
    memset( czLogDate, 0, sizeof(czLogDate) );
    GetLogDate( czLogDate, sizeof(czLogDate) );
    
    memset( czCurPath, 0, sizeof(czCurPath) );
    sprintf_s( czCurPath, sizeof(czCurPath), "%s%s_%s", m_czLogPath, czLogDate, HOOKAPI_WRITE_LOG );
    
    pFp = fopen( czCurPath, "a+" );
    if(pFp)
    {
        fprintf( pFp, "%s", pczBuf );
        fclose( pFp );
    }
}

void CBFuncExt::WriteLogApp(bool bDate, const char* pFmt, ...)
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
    
    if(bDate) sprintf_s( czPrtBuf, sizeof(czPrtBuf), "[%s] %s", czTime, czFmtBuf );
    else  sprintf_s( czPrtBuf, sizeof(czPrtBuf), "%s", czFmtBuf );

    printf("%s", czPrtBuf );
    WriteLog( czPrtBuf );
}


void CBFuncExt::WriteLogHookAPI(const char* pczFuncName, const char* pFmt, ...)
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
	sprintf_s( czPrtBuf, sizeof(czPrtBuf), "[%s] %s%s \n", czTime, pczFuncName, czFmtBuf );
    printf("%s", czPrtBuf );    
    WriteLog( czPrtBuf );

}


void CBFuncExt::GetBufferFormat(char* pczOutBuf, int nMaxOutBuf, const char* pFmt, ...)
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


void CBFuncExt::HookFuncTest()
{


}


