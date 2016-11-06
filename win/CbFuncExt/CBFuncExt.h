
#ifndef _CBFUNC_EXT_H_
#define _CBFUNC_EXT_H_

#include <Windows.h>

#define MAX_TIME     32
//#define MAX_PATH    260
#define MAX_BUF_1K 1024
#define MAX_BUF_2K 2048
#define MAX_BUF_4K 4096

#ifdef __cplusplus
extern "C"
{
#endif
    
#ifdef CBEXT_EXPORTS
#define CBEXT_API __declspec(dllexport)
#else
#define CBEXT_API __declspec(dllimport)
#endif
    
bool SHook_Init(); 
bool SHook_Uninit();
bool SHook_Install(int nPID);
bool SHook_Uninstall();

class CBFuncExt
{
public:
    CBFuncExt();
    ~CBFuncExt();    
public:
    bool Init();
    bool Uninit();
    bool Install();
    bool Uninstall();
    
    bool SetLogPath();
    bool GetProcessPath(DWORD dwPID, char* pczOutPath, int nMaxOutPath );
	DWORD GetProcessID(const char* pczProcName);
	DWORD GetProcessName(char* pczProcName, int nMaxProcName);
    
public:
    bool UnhookAPI_Calls();
    bool HookAPI_Calls();
      
public:
    void HookFuncTest();

    void GetBufferFormat(char* pczOutBuf, int nMaxOutBuf, const char* pFmt, ... );
    void WriteLogApp(bool bDate, const char* pFmt, ...);
    void WriteLogHookAPI(const char* pczFuncName, const char* pFmt, ...);
    
protected:
    void WriteLog(char* pczBuf);
    void GetLogDate(char* pczCurDate, int nMaxCurDate );
    void GetLogDateTime(char* pczCurTime, int nTimeBufSize);
    
private:
    bool m_bInit;
    int  m_nPID;
    char m_czLogPath[MAX_PATH];
    
};
	

extern CBFuncExt g_PIApi;

    
#ifdef __cplusplus
}
#endif 



#endif
