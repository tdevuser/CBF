
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libproc.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <mach/machine.h>
#include <cups/cups.h>
#include "HookInject.h"
#include "MachInject.h"

#define INJECT_PROC  "TextEdit"
#define INJECT_PISecSmartDrvTest "PISecSmartDrvTest"

#define HOOK_LIB_NAME "PIProtectorAPI.dylib"
#define HOOK_LIB_PATH "/usr/local/Privacy-i/PIProtectorAPI.dylib"

extern void InstallHook( ptrdiff_t offset, void* pParam, size_t pSize, void* pDummy);


void HookFuncTest()
{
    int  nFile=0, nPos=0, nLength=0;
    int  nToRead=0;
    char czBuf[100];
    
    for(nPos=0; nPos<10; nPos++)
    {
        nFile = open( "./test1.txt", O_CREAT | FREAD | FWRITE | O_EXCL );
        if(nFile < 0) continue;
        
        nToRead = sizeof(czBuf);
        memset( czBuf, 0, nToRead );
        nLength = (int)read( nFile, czBuf, nToRead );
        
        close( nFile );
        rand();
    }
}



void CUPS_TestPrintAPI_00()
{
    cups_dest_t *dests;
    int num_dests = cupsGetDests(&dests);
    cups_dest_t* dest = cupsGetDest("name", NULL, num_dests, dests);
    
    if(dest && dest->name)
    {
        printf("%s \n", dest->name );
    }
    /* do something with dest */
    
    cupsFreeDests(num_dests, dests);
}


void CUPS_TestPrintAPI_01()
{
    int job_id;
    int i;
    char buffer[1024];
    
    
    /* If the job is created, add 10 files */
    //  if (job_id > 0)
    {
        for (i = 1; i <= 3; i ++)
        {
            snprintf(buffer, sizeof(buffer), "file%d.txt", i);
            
            cupsStartDocument(CUPS_HTTP_DEFAULT, "MyPrint", job_id, buffer,
                              CUPS_FORMAT_TEXT, i == 10);
            
            snprintf(buffer, sizeof(buffer),
                     "File %d\n"
                     "\n"
                     "One fish,\n"
                     "Two fish,\n"
                     "Red fish,\n"
                     "Blue fish\n", i);
            
            /* cupsWriteRequestData can be called as many times as needed */
            cupsWriteRequestData(CUPS_HTTP_DEFAULT, buffer, strlen(buffer));
            
            cupsFinishDocument(CUPS_HTTP_DEFAULT, "MyPrinter" );
        }
    }
}

#include <mach/mach_init.h>
#include <mach/mach.h>
#include <mach/mach_traps.h>

int main(int argc, const char * argv[])
{
    bool  bSuc = 0;
    pid_t nInjPid=0;
    cpu_type_t nCpuType = 0;
    const char* pczProcName = NULL;
    const char* pczLibName = NULL;
    
    if(argc < 2) return -1;
    if(getuid() > 0) return -1;

    pczLibName  = argv[1];
    if(!pczLibName) return -1;
    
    pczProcName = argv[2];
    if(!pczProcName)
    {
        bSuc = g_Inject.InjectAll( pczLibName );
        if(!bSuc)
        {
        }        
        sleep( 5000 );
        return 0;
    }
    
    nInjPid = g_Inject.GetProcessID( (char*)pczProcName );
    if(!nInjPid)
    {
        printf("process not found. \n"  );
        return 0;
    }
    
    nCpuType = 0;
    bSuc = g_Inject.FetchCpuType( nInjPid, &nCpuType );
    if(true == bSuc)
    {
        if(nCpuType == CPU_TYPE_X86_64)
        {
            printf( "[%s] uid=%d, pid=%d, proc=%s, 64 bit. \n", __FUNCTION__, getuid(), nInjPid, argv[1] );
        }
        else if(nCpuType == CPU_TYPE_X86)
        {
            printf( "[%s] uid=%d, pid=%d, proc=%s, 34 bit. \n", __FUNCTION__, getuid(), nInjPid, argv[1] );
        }
    }
    
    bSuc = g_Inject.Inject( nInjPid, pczLibName );
    if(!bSuc)
    {
    }
    return 0;
}


