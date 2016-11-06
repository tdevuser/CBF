
#include "HookDefMain.h"
#include "CBFuncExt.h"
#include "HookCode.h"
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#pragma warning(disable:4819)

extern CHookCode g_Hook;
extern CBFuncExt g_PIApi;

// open();
int (*g_fpnext_open)(const char* pczFileName, int nFlags);
int next_open(const char* pczFileName, int nFlags)
{
    char czBuf[10];
    memset(czBuf, 0, sizeof(czBuf) );
    memset(czBuf, 0, sizeof(czBuf) );
    memset(czBuf, 0, sizeof(czBuf) );
    return 0;
}
int hook_open(const char* pczFileName, int nFlags)
{
    int nRet = 0;
    nRet = g_fpnext_open( pczFileName, nFlags );
    g_PIApi.WriteLogHookAPI( __FUNCTION__, "( %s, %d ), %d", pczFileName, nFlags, nRet );
    return nRet;
}

// read();
int (*g_fpnext_read)(int fd, void* pBuf, size_t nBytes );
int next_read(int fd, void* pBuf, size_t nBytes )
{
    char czBuf[10];
    memset(czBuf, 0, sizeof(czBuf) );
    memset(czBuf, 0, sizeof(czBuf) );
    memset(czBuf, 0, sizeof(czBuf) );
    return 0;
}
int hook_read(int fd, void* pBuf, size_t nBytes )
{
    int  nRet = 0;
    nRet = g_fpnext_read( fd, pBuf, nBytes );
    g_PIApi.WriteLogHookAPI( __FUNCTION__, "( %d, %p, %d ), %d", fd, pBuf, nBytes, nRet );
    return nRet;
}

// write();
int (*g_fpnext_write)(int fd, const void* pBuf, size_t nCount);
int next_write(int fd, const void* pBuf, size_t nCount)
{
    char czBuf[10];
    memset(czBuf, 0, sizeof(czBuf) );
    memset(czBuf, 0, sizeof(czBuf) );
    memset(czBuf, 0, sizeof(czBuf) );
    return 0;
}
int hook_write(int fd, const void* pBuf, size_t nCount)
{
    int nRet = 0;
    nRet = g_fpnext_write( fd, pBuf, nCount );
    g_PIApi.WriteLogHookAPI( __FUNCTION__, "( %d, %p, %d ), %d", fd, pBuf, nCount, nRet );
    return nRet;
}

// close();
int (*g_fpnext_close)(int fd);
int next_close(int fd)
{
    char czBuf[10];
    memset(czBuf, 0, sizeof(czBuf) );
    memset(czBuf, 0, sizeof(czBuf) );
    memset(czBuf, 0, sizeof(czBuf) );
    return -1;
}
int hook_close(int fd)
{
    int nRet = 0;
    nRet = g_fpnext_close(fd);
    g_PIApi.WriteLogHookAPI( __FUNCTION__, "( %d ), %d", fd, nRet );
    return nRet;
}



