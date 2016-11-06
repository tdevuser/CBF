
#ifndef _CBFUNC_API_H_
#define _CBFUNC_API_H_

#include <iostream.h>
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* The classes below are exported */
#pragma GCC visibility push(default)


#define MAX_TIME     32
#define MAX_PATH    260
#define MAX_BUF_1K 1024
#define MAX_BUF_2K 2048
#define MAX_BUF_4K 4096


#ifdef __cplusplus
extern "C"
{
#endif
    
    
bool SHook_Init() __attribute ((constructor));
bool SHook_Uninit() __attribute__ ((destructor));

bool SHook_Install(pid_t nPID);
bool SHook_Uninstall();

    
class CBFuncAPI
{
public:
    CBFuncAPI();
    ~CBFuncAPI();
    
public:
    bool Init();
    bool Uninit();
    bool Install(pid_t nPID);
    bool Uninstall();
    
    bool SetLogPath();
    bool SetLogPath(pid_t nPID);
    pid_t GetProcessID(const char* pczProcName);
    bool GetProcessPath(pid_t nPID, char* pczOutPath, uint32_t nMaxOutPath );
    
public:
    bool UnhookAPI_Calls();
    bool HookAPI_Calls();
    
public:
    void GetBufferFormat(char* pczOutBuf, uint32_t nMaxOutBuf, const char* pFmt, ... );
    void WriteLogApp(bool bDate, const char* pFmt, ...);
    void WriteLogHookAPI(const char* pczFuncName, const char* pFmt, ...);
    
protected:
    void WriteLog(char* pczBuf);
    void GetLogDate(char* pczCurDate, int nMaxCurDate );
    void GetLogDateTime(char* pczCurTime, int nTimeBufSize);
    
private:
    bool  m_bInit;
    pid_t m_nPID;
    char  m_czLogPath[MAX_PATH];
    
};
    


    
    
#ifdef __cplusplus
}
#endif 

#pragma GCC visibility pop

#endif
