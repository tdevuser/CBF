
#include "HookCode.h"
#include "CodeSect.h"
#include "CBFuncExt.h"
#include <stdlib.h>

#pragma warning(disable:4819)
#pragma warning(disable:4995)
#pragma warning(disable:4996)


#define NOP 0x90


#if defined( _M_X64 )
    #include "./hde/hde64.h"
    typedef hde64s HDE;
    #define HDE_DISASM(code, hs) hde64_disasm(code, hs)
#elif  defined ( _M_IX86 )
    #include "./hde/hde32.h"
    typedef hde32s HDE;
    #define HDE_DISASM(code, hs) hde32_disasm(code, hs)
#endif


CHookCode g_Hook;
extern CBFuncExt g_PIApi;


#if defined( _M_X64 )
    CALL_ABS g_Call =
    {
        0xFF, 0x15, 0x00000002, // FF15 00000002: CALL [RIP+8]
        0xEB, 0x08,             // EB 08:         JMP +10
        0x0000000000000000ULL   // Absolute destination address
    };
    JMP_ABS g_Jump =
    {
        0xFF, 0x25, 0x00000000, // FF25 00000000: JMP [RIP+6]
        0x0000000000000000ULL   // Absolute destination address
    };
    JCC_ABS g_Jcc =
    {
        0x70, 0x0E,             // 7* 0E:         J** +16
        0xFF, 0x25, 0x00000000, // FF25 00000000: JMP [RIP+6]
        0x0000000000000000ULL   // Absolute destination address
    };
    CMD_ABS_7 g_Cmd7 =
    {
        0x00, 0x00, 0x00, 0x00000002, // 0x48 0x8B 0x5D 00000002: CALL [RIP+8]
        0xEB, 0x08,                   // EB 08:         JMP +10
        0x0000000000000000ULL         // Absolute destination address
    };
    CMD_ABS_6 g_Cmd6 =
    {
        0x00, 0x00, 0x00000002,       // 0x8B 0x5D 00000002: CALL [RIP+8]
        0xEB, 0x08,                   // EB 08:         JMP +10
        0x0000000000000000ULL         // Absolute destination address
    };
#elif defined( _M_IX86 )
    CALL_REL g_Call =
    {
        0xE8,                   // E8 xxxxxxxx: CALL +5+xxxxxxxx
        0x00000000              // Relative destination address
    };
    JMP_REL g_Jump =
    {
        0xE9,                   // E9 xxxxxxxx: JMP +5+xxxxxxxx
        0x00000000              // Relative destination address
    };
    JCC_REL g_Jcc =
    {
        0x0F, 0x80,             // 0F8* xxxxxxxx: J** +6+xxxxxxxx
        0x00000000              // Relative destination address
    };
#endif


CHookCode::CHookCode() : m_pHead(NULL), m_nMaxLength(0), m_nMaxPos(0), m_nPos(0)
{
}

CHookCode::~CHookCode()
{
}

bool CHookCode::Initialize()
{
	InitializeCriticalSection( &m_csLockHook );

    CodeSectInit();
    return true;
}

bool CHookCode::Finalize()
{
    HookData_DeleteAll();
    
	DeleteCriticalSection( &m_csLockHook );
    return true;
}

void* CHookCode::FetchAddress( const char* pczLibName, const char* pczFuncName )
{
    void* pHandle = NULL;
    void* pFuncAddr = NULL;
	HMODULE  hLib = NULL;

	hLib = LoadLibraryA( pczLibName  );
	if(!hLib) 
	{
		return NULL;
	}
    
	pFuncAddr = (void*)GetProcAddress( hLib, pczFuncName );
    if(!pFuncAddr)
    {
        printf("[%s] dlsym( %s ), Error=%s \n", __FUNCTION__, pczLibName, GetLastError() );
        return NULL;
    }
    return pFuncAddr;
}


void CHookCode::DisplayOPCode(const char* pczTitle, void* pAddress, int nLength)
{
    PBYTE pOPCode = NULL;
    
    if(!pAddress) return;
    
    pOPCode = (PBYTE)pAddress;
    
    g_PIApi.WriteLogApp(true, "%s %p> ", pczTitle, pAddress);
    for(int i=0; i<nLength; i++)
    {
        g_PIApi.WriteLogApp(false, "%02X ", pOPCode[i] );
    }
    g_PIApi.WriteLogApp(false, "\n");
}


bool CHookCode::UpdateNextCommand(PHookData pHookInfo)
{
    bool bSuc = false;
    void* pFuncAddr = NULL;
    void* pNextAddr = NULL;
    void* pFuncPos  = NULL;
    void* pNextPos  = NULL;
    void* pDestAddr = NULL;
    void* pJumpDestAddr = NULL;
    int   nCopySize=0, nLength=0, nOldPos=0, nNextPos=0;
    int   nOldSize=0, nHookSize=0, nNextSize=0;
    HDE   HCmd;
    BYTE  czInstBuf[SIZE_CODESECT];
	DWORD dwOldProtect = 0;
    
#if defined( _M_X64 )
    CALL_ABS Call = g_Call;
    JMP_ABS  Jump = g_Jump;
    JCC_ABS  Jcc  = g_Jcc;
#elif defined( _M_IX86 )
	CALL_REL Call = g_Call;
    JMP_REL  Jump = g_Jump;
    JCC_REL  Jcc  = g_Jcc;
#endif
    
    nOldSize  = pHookInfo->nOldSize;
    nHookSize = pHookInfo->nHookSize;
    pFuncAddr = pHookInfo->pBaseAddress;
    pNextAddr = pHookInfo->pNextAddress;
    
	VirtualProtect( pNextAddr, nNextSize, PAGE_EXECUTE_READWRITE, &dwOldProtect );
    while(nLength < nOldSize)
    {
        pFuncPos = (void*)((ULONG)pFuncAddr + nOldPos);
        pNextPos = (void*)((ULONG)pNextAddr + nNextPos);
        
        nCopySize = HDE_DISASM( pFuncPos, &HCmd );
        
        memset( czInstBuf, NOP, sizeof(czInstBuf) );
        memcpy( czInstBuf, pFuncPos, nCopySize );
        
        if(HCmd.modrm_mod == 0 && HCmd.modrm_rm == 0x05)
        {
#if defined(__x86_64__)
            // Instructions using RIP relative addressing. (ModR/M = 00???101B), // Modify the RIP relative address.
            /*
             UINT32* pRelAddr = NULL;
             // Relative address is stored at (instruction length - immediate value length - 4).
             pRelAddr  = (UINT32*)((ULONG)czInstBuf + HCmd.len - ((HCmd.flags & 0x3C) >> 2) - 4);
             *pRelAddr = (UINT32)((ULONG)pFuncPos + HCmd.len + (INT32)HCmd.disp.disp32) - ((ULONG)pNextPos + HCmd.len);
             */
            
            // 0x05, 0x0D, 0x15, 0x1D, 0x25, 0x2D, 0x35, 0x3D
            PUINT64 pAddress = NULL;
            
            pAddress = (PUINT64)((ULONG)pFuncPos + HCmd.len + (INT32)HCmd.disp.disp32);
            if(HCmd.opcode == 0xFF)
            {
                if(HCmd.modrm == 0x05 || HCmd.modrm == 0x0D)
                { // INC // DEC
                }
                else if(HCmd.modrm == 0x15)
                {
                    Call = g_Call;
                    Call.address = (UINT64)(*pAddress);
                    
                    nCopySize = sizeof(Call);
                    memset( czInstBuf, NOP, sizeof(czInstBuf) );
                    memcpy( czInstBuf, &Call, nCopySize );
                }
                else if(HCmd.modrm == 0x25)
                {
                    Jump = g_Jump;
                    Jump.address = (UINT64)(*pAddress);
                    
                    nCopySize = sizeof(Jump);
                    memset( czInstBuf, NOP, sizeof(czInstBuf) );
                    memcpy( czInstBuf, &Jump, nCopySize );
                }
                else if(HCmd.modrm == 0x35)
                {
                    printf("push command \n" );
                }
            }
            else if(HCmd.opcode == 0x0F)
            {
                printf("[%s] RIP Relative Addressing. 2Byte Opcode == 0x0F. \n", __FUNCTION__ );
            }
            else
            {
                if(HCmd.len == 7)
                {
                    CMD_ABS_7 Cmd7 = g_Cmd7;
                    Cmd7.opcode[0] = czInstBuf[0]; // rex prefix
                    Cmd7.opcode[1] = czInstBuf[1]; // opcode
                    Cmd7.opcode[2] = czInstBuf[2]; // modrm
                    Cmd7.address = (UINT64)pAddress;
                    nCopySize = sizeof(Cmd7);
                    memset( czInstBuf, NOP, sizeof(czInstBuf) );
                    memcpy( czInstBuf, &Cmd7, nCopySize );
                    printf("[%s] RIP Relative Addressing. 7BYTE. HCmd.len=%d \n", __FUNCTION__, HCmd.len );
                }
                else if(HCmd.len == 6)
                {
                    CMD_ABS_6 Cmd6 = g_Cmd6;
                    Cmd6.opcode[0] = czInstBuf[0]; // opcode
                    Cmd6.opcode[1] = czInstBuf[1]; // modrm
                    Cmd6.address = (UINT64)pAddress;
                    nCopySize = sizeof(Cmd6);
                    memset( czInstBuf, NOP, sizeof(czInstBuf) );
                    memcpy( czInstBuf, &Cmd6, nCopySize );
                    
                    printf("[%s] RIP Relative Addressing. 6BYTE. HCmd.len=%d \n", __FUNCTION__, HCmd.len );
                }
                else
                {
                    printf("[%s] RIP Relative Addressing. Except. HCmd.len=%d \n", __FUNCTION__, HCmd.len );
                }
            }
#endif
        }
        else if(HCmd.opcode == 0xE8)
        {
            Call = g_Call;
            pDestAddr = (void*)((ULONG)pFuncPos + HCmd.len + (INT32)HCmd.imm.imm32);
            
#if defined(__x86_64__)
            Call.address = (UINT64)pDestAddr;
#elif defined(__i386__)
            Call.operand = (UINT32)(pDestAddr - (pNextPos + sizeof(Call)) );
#endif
            nCopySize = sizeof(Call);
            memset( czInstBuf, NOP, sizeof(czInstBuf) );
            memcpy( czInstBuf, &Call, nCopySize );
        }
        else if((HCmd.opcode & 0xFD) == 0xE9)
        {   // Direct relative JMP (0xEB or 0xE9)
            Jump = g_Jump;
            pDestAddr = (void*)((ULONG)pFuncPos  + HCmd.len);
            if(HCmd.opcode == 0xEB)
            { // Short Jump
                pDestAddr = (void*)((ULONG)pDestAddr + (INT8)HCmd.imm.imm8);
            }
            else
            { // long Jump
                pDestAddr = (void*)((ULONG)pDestAddr + (INT32)HCmd.imm.imm32);
            }
            
            // internal jmp
            if(pDestAddr >= pFuncAddr && pDestAddr < (void*)((ULONG)pFuncAddr + sizeof(JMP_REL)) )
            {
                if(pJumpDestAddr < pDestAddr)
                {
                    pJumpDestAddr = pDestAddr;
                }
            }
            else
            {
#if defined(__x86_64__)
                Jump.address = (UINT64)pDestAddr;
#elif defined(__i386__)
                Jump.operand = (UINT32)((ULONG)pDestAddr - (pNextPos + sizeof(Jump)) );
#endif
                nCopySize = sizeof(Jump);
                memset( czInstBuf, NOP, sizeof(czInstBuf) );
                memcpy( czInstBuf, &Jump, nCopySize );
            }
        }
        else if((HCmd.opcode  & 0xF0) == 0x70 || (HCmd.opcode  & 0xFC) == 0xE0 || (HCmd.opcode2 & 0xF0) == 0x80)
        {   // Jcc // LOOPNZ / LOOPZ / LOOP / JECXZ // Relative Jcc
            Jcc = g_Jcc;
            pDestAddr = (void*)((ULONG)pFuncPos + HCmd.len);
            // Jcc // LOOPNZ / LOOPZ / LOOP / JECXZ
            if( (HCmd.opcode & 0xF0) == 0x70 || (HCmd.opcode & 0xE0) == 0xE0 )
            {
                pDestAddr = (void*)((ULONG)pDestAddr + HCmd.imm.imm8);
            }
            else
            {
                pDestAddr = (void*)((ULONG)pDestAddr + HCmd.imm.imm32);
            }
            // Internal Jump
            if(pDestAddr >= pFuncAddr && pDestAddr < (void*)((ULONG)pFuncAddr + sizeof(JMP_REL)))
            {
                if(pJumpDestAddr < pDestAddr)
                {
                    pJumpDestAddr = pDestAddr;
                }
            }
            else if((HCmd.opcode & 0xFC) == 0xE0)
            {
                return false;
            }
            else
            {
                UINT8 cbCondition = ((HCmd.opcode != 0x0F ? HCmd.opcode : HCmd.opcode2) & 0x0F);
#if defined(__x86_64__)
                Jcc.opcode  = 0x71 ^ cbCondition;
                Jcc.address = (UINT64)pDestAddr;
#elif defined(__i386__)
                Jcc.opcode1 = 0x80 | cbCondition;
                Jcc.operand = (UINT32)((ULONG)pDestAddr - (pNextPos + sizeof(Jcc)));
#endif
                nCopySize = sizeof(Jcc);
                memset( czInstBuf, NOP, sizeof(czInstBuf) );
                memcpy( czInstBuf, &Jcc, nCopySize );
            }
        }
        else if((HCmd.opcode & 0xFE) == 0xC2)
        {
            printf("[%s] 0xC2 ", __FUNCTION__ );
        }
        
        bSuc = CodeSectMemcpy( pNextPos, czInstBuf, nCopySize );
        if(!bSuc) printf("[%s] CodeSectMemcpy Failed. \n", __FUNCTION__ );
        
        nNextPos += nCopySize;
        nOldPos += HCmd.len;
        nLength += HCmd.len;
        
        DisplayOPCode( "Next>", pNextPos, nCopySize );
    }
	VirtualProtect( pNextAddr, nNextSize, dwOldProtect, NULL );
 
    pHookInfo->nNextSize = nNextPos;
    return true;
}


bool CHookCode::UnhookAPI( PVOID pNextAddress )
{
    PVOID     pFuncAddr = NULL;
    PHookData pHookInfo = NULL;
    UINT32    nOldSize  = 0;
	DWORD     dwOldProtect  = 0;
	BOOL      bSuc = FALSE;
    
	::EnterCriticalSection( &m_csLockHook  );
    pHookInfo = HookData_Search( pNextAddress );
    if(!pHookInfo || pNextAddress != pHookInfo->pNextAddress)
    {
        ::LeaveCriticalSection( &m_csLockHook );
        return false;
    }
    
    nOldSize = pHookInfo->nOldSize;
    pFuncAddr = pHookInfo->pBaseAddress;
    if(!pFuncAddr || nOldSize <= 0)
    {
        ::LeaveCriticalSection( &m_csLockHook );
        return false;
    }
    //
	bSuc = VirtualProtect( pFuncAddr, nOldSize, PAGE_EXECUTE_READWRITE, &dwOldProtect );
    if(bSuc == TRUE)
    {
        memset( pFuncAddr, NOP, nOldSize );
        memcpy( pFuncAddr, pHookInfo->czOldOPCode, nOldSize );

		bSuc = VirtualProtect( pFuncAddr, nOldSize, dwOldProtect, NULL );
        if(bSuc == TRUE)
        {
            HookData_Delete( pNextAddress );
            ::LeaveCriticalSection( &m_csLockHook );
            return true;
        }
    }

	::LeaveCriticalSection( &m_csLockHook );
    return false;
}

bool CHookCode::HookAPI(const char* pczLibName, const char* pczFuncName, void* pHookAddress, void** ppNextAddress)
{
    bool bSuc = false;

    ::EnterCriticalSection( &m_csLockHook  );
    
    bSuc = HookAPI_Int( pczLibName, pczFuncName, pHookAddress, ppNextAddress );
    
    ::LeaveCriticalSection( &m_csLockHook );
    return bSuc;
}

bool CHookCode::HookAPI_Code( const char* pczLibName, const char* pczFuncName, void* pHookAddress, void* pNextAddress, int nNextSize )
{
    bool bSuc = false;

    ::EnterCriticalSection( &m_csLockHook  );
    
    bSuc = HookAPI_CodeInt( pczLibName, pczFuncName, pHookAddress, pNextAddress, nNextSize );
    
    ::LeaveCriticalSection( &m_csLockHook );
    return bSuc;
}

bool CHookCode::WriteJump_Call(PHookData pHookInfo)
{
    bool  bSuc = false;
    PBYTE pPos = NULL;
    void* pFuncAddr = NULL;
    void* pNextAddr = NULL;
    void* pPosAddr  = NULL;
    int   nLength=0, nCopySize=0;
    int   nOldSize=0, nHookSize=0, nNextSize=0;
    HDE   HCmd;
    char  czHookOPCode[SIZE_CODESECT];
    
    if(!pHookInfo) return false;
    
    // HookOPCode init
    memset(czHookOPCode, NOP, sizeof(czHookOPCode));
    nHookSize = pHookInfo->nHookSize;
    nNextSize = pHookInfo->nNextSize;
    pFuncAddr = pHookInfo->pBaseAddress;
    pNextAddr = pHookInfo->pNextAddress;
    pPos = (PBYTE)czHookOPCode;
    
    if(!pFuncAddr || !pNextAddr || !pPos || nHookSize <=0)
    {
        g_PIApi.WriteLogApp( true, "[%s] INVALID ARGUMENT - 02, %s, %s, Error. \n",
                                     __FUNCTION__, pHookInfo->pczLibName, pHookInfo->pczFuncName );
        return false;
    }
    
    g_PIApi.WriteLogApp( true, "[%s][%s] \n", __FUNCTION__, pHookInfo->pczFuncName );
    while(nLength < nHookSize)
    {
        pPosAddr = (void*)((ULONG)pFuncAddr + nLength);
        nCopySize = HDE_DISASM( pPosAddr, &HCmd );
        nLength += nCopySize;
        DisplayOPCode( "Old >", pPosAddr, nCopySize );
    }
    
    // Original Backup
    nOldSize = nLength;
    pHookInfo->nOldSize = nOldSize;
    memset( pHookInfo->czOldOPCode, NOP, sizeof(pHookInfo->czOldOPCode) );
    memcpy( pHookInfo->czOldOPCode, pFuncAddr, nOldSize );
    
    bSuc = UpdateNextCommand( pHookInfo );
    if(!bSuc)
    {
        printf( "[%s] UpdateNextCommand failed. \n", __FUNCTION__ );
    }
    
#if defined(__i386__)
    if(pPos)
    {
        pPos[0] = (BYTE)0xE9;
        int* pRVA = (int*)&pPos[1];
        *pRVA = (PBYTE)pHookInfo->pHookAddress - ((PBYTE)pFuncAddr + nHookSize);
    }
    pPos = pHookInfo->czNextOPCode + nHookSize - 5;
    if(*pPos == (BYTE)0xE8)
    {
        int nVaddr = 0;
        pPos++;
        nVaddr = (int)((PBYTE)pFuncAddr + nHookSize + (*(int*)pPos));
        *((int*)pPos) = nVaddr - (int)((PBYTE)pHookInfo->czNextOPCode + nHookSize);
    }
#elif defined(__x86_64__)
    if(pPos)
    {
        pPos[0] = (BYTE)0x48;
        pPos[1] = (BYTE)0xB8;
        uint64_t* pVaddr = (uint64_t*)&pPos[2];
        *pVaddr = (uint64_t)pHookInfo->pHookAddress;
        pPos[10] = (BYTE)0xFF;
        pPos[11] = (BYTE)0xE0;
    }
#endif
    
    bSuc = CodeSectMemset( pFuncAddr, nOldSize, NOP );
    if(!bSuc) printf("[%s] CodeSectMemset Failed. \n", __FUNCTION__ );
    
    bSuc = CodeSectMemcpy( pFuncAddr, czHookOPCode, nHookSize );
    if(!bSuc) printf("[%s] CodeSectMemory Failed. \n", __FUNCTION__ );

    return true;
}

bool CHookCode::WriteJump_Return(PHookData pHookInfo)
{
    bool  bSuc = false;
    PBYTE pPos   = NULL;
    void* pNextAddr = NULL;
    int   nOldSize=0, nHookSize=0, nNextSize=0;
    char  czHookOPCode[SIZE_CODESECT];
    
    if(!pHookInfo) return false;
    
    memset( czHookOPCode, NOP, sizeof(czHookOPCode) );
    nOldSize  = pHookInfo->nOldSize;
    nHookSize = pHookInfo->nHookSize;
    nNextSize = pHookInfo->nNextSize;
    pNextAddr = (void*)((ULONG)pHookInfo->pNextAddress + nNextSize);
    pPos = (PBYTE)czHookOPCode;
    
    if(!pNextAddr || !pPos || nOldSize <= 0 || nHookSize <=0 || nNextSize <= 0)
    {
        return false;
    }
    
#if defined(__i386__)
    if(pPos)
    {
        pPos[0] = (BYTE)0xE9;
        uint32_t* pAddr = (uint32_t*)&pPos[1];
        *pAddr = ((PBYTE)pHookInfo->pBaseAddress + nOldSize) - ((PBYTE)pNextAddr + nHookSize);
    }
#elif defined(__x86_64__)
    if(pPos)
    {
        pPos[0] = (BYTE)0x48;
        pPos[1] = (BYTE)0xB8;
        uint64_t* pAddr = (uint64_t*)&pPos[2];
        *pAddr = (uint64_t)((PBYTE)pHookInfo->pBaseAddress + nOldSize);
        pPos[10] = (BYTE)0xFF;
        pPos[11] = (BYTE)0xE0;
    }
#endif
    
    pHookInfo->nNextSize = nNextSize + nHookSize;
    
    bSuc = CodeSectMemcpy( pNextAddr, czHookOPCode, nHookSize );
    if(!bSuc) printf("[%s] CodeSectMemcpy Failed. \n", __FUNCTION__ );
    
    DisplayOPCode( "Next>", pNextAddr, nHookSize );
    DisplayOPCode( "Old >", pHookInfo->pBaseAddress, pHookInfo->nOldSize );
    
    g_PIApi.WriteLogApp( true, "[%s][%s] nOld=%d, nNext=%d. \n\n",
                                 __FUNCTION__,
                                 pHookInfo->pczFuncName, pHookInfo->nOldSize, pHookInfo->nNextSize );
    return true;
}


bool CHookCode::HookAPI_Int( const char* pczLibName, const char* pczFuncName, void* pHookAddress, void** ppOutNextAddress )
{
    int   nLength=0, nOldSize=0, nHookSize=0;
    void* pHandle   = NULL;
    void* pFuncAddr = NULL;
    void* pNextAddr = NULL;
    PHookData pHookInfo = NULL;
    
    if(!pczLibName || !pczFuncName || !pHookAddress || !ppOutNextAddress)
    {
        g_PIApi.WriteLogApp( true, "[%s] ( %s, %s ) INVALID_ARGUMENT. \n", __FUNCTION__, pczLibName, pczFuncName );
        return false;
    }
    
    nHookSize = SIZE_HOOKCODE;    
    pFuncAddr = FetchAddress( pczLibName, pczFuncName );
    if(!pFuncAddr)
    {
        g_PIApi.WriteLogApp( true, "[%s] FechMachAddress, %s, %s, Error. \n", __FUNCTION__, pczLibName, pczFuncName );
        return false;
    }
    
    pNextAddr = CodeSectAlloc();
    if(!pNextAddr)
    {
        g_PIApi.WriteLogApp( true, "[%s] CodeSectAlloc, %s, %s, Error. \n", __FUNCTION__, pczLibName, pczFuncName );
        return false;
    }
    
    nOldSize = nLength;
    pHookInfo = HookData_malloc( pczLibName, pczFuncName );
    if(!pHookInfo)
    {
        CodeSectFree( pNextAddr );
        g_PIApi.WriteLogApp( true, "[%s] HookData_malloc, %s, %s, Error. \n", __FUNCTION__, pczLibName, pczFuncName );
        return false;
    }
    
    pHookInfo->bInternNext  = true;
    pHookInfo->pBaseAddress = pFuncAddr;
    pHookInfo->pHookAddress = pHookAddress;
    pHookInfo->pNextAddress = pNextAddr;
    pHookInfo->nHookSize    = nHookSize;
    pHookInfo->nNextSize    = 0;
    pHookInfo->nOldSize     = 0;
    
    WriteJump_Call( pHookInfo );
    
    WriteJump_Return( pHookInfo );
    
    if(true == HookData_Append( pHookInfo ))
    {
        (*ppOutNextAddress) = (void*)pHookInfo->pNextAddress;
    }
    else
    {
        if(true == pHookInfo->bInternNext)
        {
            CodeSectFree( pNextAddr );
        }
        
        HookData_free( pHookInfo );
        g_PIApi.WriteLogApp( true, "[%s] HookData_Append, %s, %s, Error. \n", __FUNCTION__, pczLibName, pczFuncName );
        return false;
    }
    return true;
}


bool CHookCode::HookAPI_CodeInt( const char* pczLibName, const char* pczFuncName, void* pHookAddress, void* pNextAddress, int nNextSize )
{
    bool  bSuc = false;
    int   nHookSize = 0;
    void* pFuncAddr  = NULL;
    PHookData pHookInfo  = NULL;
    
    if(!pczLibName || !pczFuncName || !pHookAddress || !pNextAddress)
    {
        g_PIApi.WriteLogApp( true, "[%s] INVALID ARGUMENT, %s, %s, Error. \n", __FUNCTION__, pczLibName, pczFuncName );
        return false;
    }
    
    nHookSize = SIZE_HOOKCODE;
    pFuncAddr = FetchAddress( pczLibName, pczFuncName );
    if(!pFuncAddr)
    {
        g_PIApi.WriteLogApp( true, "[%s] FetchMachAddress, %s, %s, Error. \n", __FUNCTION__, pczLibName, pczFuncName );
        return false;
    }
    
    pHookInfo = HookData_malloc( pczLibName, pczFuncName );
    if(!pHookInfo)
    {
        g_PIApi.WriteLogApp( true, "[%s] HookData_malloc, %s, %s, Error. \n", __FUNCTION__, pczLibName, pczFuncName );
        return false;
    }
    
    pHookInfo->bInternNext = false;
    pHookInfo->pBaseAddress = pFuncAddr;
    pHookInfo->pHookAddress = pHookAddress;
    pHookInfo->pNextAddress = pNextAddress;
    pHookInfo->nHookSize = nHookSize;
    pHookInfo->nNextSize = 0;
    pHookInfo->nOldSize  = 0;
    
    WriteJump_Call( pHookInfo );
    
    WriteJump_Return( pHookInfo );
    
    bSuc = HookData_Append( pHookInfo );
    if(!bSuc)
    {
        HookData_free( pHookInfo );
        g_PIApi.WriteLogApp( true, "[%s] HookData_Append, %s, %s, Error. \n", __FUNCTION__, pczLibName, pczFuncName );
        return false;
    }
    return true;
}


PHookData CHookCode::HookData_malloc( const char* pczLibName, const char* pczFuncName )
{
    int       nLength = 0;
    PHookData pNew = NULL;
    
    nLength = sizeof(HookData);
    pNew = (PHookData)new HookData();
    if(!pNew)
    {
        return NULL;
    }
    
    memset( pNew, 0, nLength );
    nLength = (int)strlen(pczLibName);
    pNew->pczLibName = (char*)new char[nLength+1];
    if(pNew->pczLibName)
    {
        memset( pNew->pczLibName, 0, nLength );
        strncpy( pNew->pczLibName, pczLibName, nLength );
    }
    
    nLength = (int)strlen(pczFuncName);
    pNew->pczFuncName = (char*)new char[nLength+1];
    if(pNew->pczFuncName)
    {
        memset( pNew->pczFuncName, 0, nLength );
        strncpy( pNew->pczFuncName, pczFuncName, nLength );
    }
    return pNew;
}


void CHookCode::HookData_free( PHookData pHookData )
{
    if(!pHookData)
    {
        return;
    }
    
    if(pHookData->pczFuncName)
    {
        delete[] pHookData->pczFuncName;
        pHookData->pczFuncName = NULL;
    }
    
    if(pHookData->pczLibName)
    {
        delete[] pHookData->pczLibName;
        pHookData->pczLibName = NULL;
    }
    
    delete pHookData;
    pHookData = NULL;
}


PHookData CHookCode::HookData_Search( const char* pczLibName, const char* pczFuncName )
{
    PHookData pPos = NULL;
    
    if(!pczLibName || !pczFuncName) return NULL;
    
    pPos = m_pHead;
    while(pPos)
    {
        if(!strnicmp(pPos->pczLibName, pczLibName, strlen(pczLibName)) && !strnicmp(pPos->pczFuncName, pczFuncName, strlen(pczFuncName)))
        {
            return pPos;
        }
        pPos = pPos->pNext;
    }
    return NULL;
}


PHookData CHookCode::HookData_Search( PVOID pNextAddress )
{
    PHookData pPos = NULL;
    
    if(!pNextAddress) return NULL;
    
    pPos = m_pHead;
    while(pPos)
    {
        if(pPos->pNextAddress == pNextAddress)
        {
            return pPos;
        }
        pPos = pPos->pNext;
    }
    return NULL;
}


bool CHookCode::HookData_Append( PHookData pHookData )
{
    PHookData pPos = NULL;
    
    if(!pHookData) return false;
    
    pPos = m_pHead;
    if(!pPos)
    {
        m_pHead = pHookData;
        return true;
    }
    else
    {
        while(pPos->pNext)
        {
            pPos = pPos->pNext;
        }
        pPos->pNext = pHookData;
        return true;
    }
    return false;
}

                         
bool CHookCode::HookData_Delete( PVOID pNextAddress )
{
    PHookData pPos  = NULL;
    PHookData pDel  = NULL;
    PHookData pPrev = NULL;
    
    pPos = m_pHead;
    while(pPos)
    {
        pDel = pPos;
        pPos = pPos->pNext;
        if((void*)pDel->pNextAddress == pNextAddress)
        {
            if(!pPrev) m_pHead = pPos;
            else pPrev->pNext = pPos;
            
            if(true == pDel->bInternNext)
            {
                CodeSectFree( pNextAddress );
            }
            free( pDel );
            return true;
        }
        pPrev = pDel;
    }
    return false;
}
                         

void CHookCode::HookData_DeleteAll()
{
    PHookData pPos = NULL;
    pPos = m_pHead;
    while(pPos)
    {
        UnhookAPI( pPos->pNextAddress );
        pPos = pPos->pNext;
    }
    m_pHead = NULL;
    m_nPos = 0;
}

bool CHookCode::CodeSectInit()
{
    void* pSectAddr = NULL;
    
    m_nMaxLength = (UINT32)((ULONG)SectionLimit - (ULONG)SectionBase);
    m_nMaxPos = m_nMaxLength/SIZE_CODESECT;
    
    pSectAddr = (void*)SectionBase;
    if(!pSectAddr)
    {
        m_nPos = m_nMaxPos = m_nMaxLength = 0;
        g_PIApi.WriteLogApp( true,
                             "[%s] Failed. SectBase=%p, Length=%d, MaxPos=%d, Pos=%d \n",
                            __FUNCTION__, pSectAddr, m_nMaxLength, m_nMaxPos, m_nPos );
        return false;
    }
    
    CodeSectMemset( pSectAddr, m_nMaxLength, NOP );
    g_PIApi.WriteLogApp( true,
                         "[%s] Sucess. SectBase=%p, Length=%d, MaxPos=%d, Pos=%d \n",
                         __FUNCTION__, pSectAddr, m_nMaxLength, m_nMaxPos, m_nPos );
    return true;
}

int CHookCode::GetCodeSectPos()
{
    return m_nPos;
}

int CHookCode::GetCodeSectMaxPos()
{
    return m_nMaxPos;
}

int CHookCode::GetCodeSectLength()
{
    return m_nMaxLength;
}


void* CHookCode::CodeSectAlloc()
{
    PBYTE pPos = NULL;
    void* pSectPos = NULL;
    int  nPos=0, nMaxPos=0, nOffset=0;
    
    pSectPos = (void*)SectionBase;
    if(!pSectPos)
    {
        g_PIApi.WriteLogApp( true, "[%s] INVALID_ARGUMENT Error=%s. \n", __FUNCTION__, strerror(errno) );
        return NULL;
    }
    
    nMaxPos = (m_nMaxPos-1);
    if(m_nPos < nMaxPos)
    {
        nOffset = SIZE_CODESECT*m_nPos;
#if defined (__x86_64__)
        pPos = (PBYTE)((ULONG)pSectPos + nOffset);
#elif defined (__i386__)
        pPos = (PBYTE)((int)pSecPos + nOffset);
#endif
        if(pPos && *pPos == NOP && *(pPos+1) == NOP && *(pPos+2) == NOP && *(pPos+3) == NOP)
        {
            m_nPos++;
            CodeSectMemset( pPos, sizeof(int), 0x00 );
            return (void*)pPos;
        }
    }
    else
    {
        for(nPos=0; nPos<nMaxPos; nPos++)
        {
            nOffset = SIZE_CODESECT*nPos;
#if defined (__x86_64__)
            pPos = (PBYTE)((ULONG)pSectPos + nOffset);
#elif defined (__i386__)
            pPos = (PBYTE)((int)pSecPos + nOffset);
#endif
            if(pPos && *pPos == NOP && *(pPos+1) == NOP && *(pPos+2) == NOP && *(pPos+3) == NOP)
            {
                CodeSectMemset( pPos, sizeof(int), 0x00 );
                return (void*)pPos;
            }
        }
    }
    return NULL;
}

void CHookCode::CodeSectFree(void* pSectAddr)
{
    if(!pSectAddr) return;

    CodeSectMemset( pSectAddr, SIZE_CODESECT, NOP );
}


bool CHookCode::CodeSectMemset( void* pSectAddr, int nCodeSize, BYTE cValue )
{
    BOOL bSuc = FALSE;
	DWORD dwOldProtect = 0;

    if(!pSectAddr) return false;
    
	bSuc = VirtualProtect( pSectAddr, nCodeSize, PAGE_EXECUTE_READWRITE, &dwOldProtect );
    if(!bSuc)
    {
        printf("[%s] pSectAddr=%p, Length=%d vm_protect Failed. 01 \n", __FUNCTION__, pSectAddr, nCodeSize );
        return false;
    }
    
    memset( pSectAddr, cValue, nCodeSize );
    
	bSuc = VirtualProtect( pSectAddr, nCodeSize, dwOldProtect, NULL );
    if(!bSuc)
    {
        printf("[%s] pSectAddr=%p, Length=%d vm_protect Failed. 02 \n", __FUNCTION__, pSectAddr, nCodeSize );
        return false;
    }
    
    return true;
}


bool CHookCode::CodeSectMemcpy(void* pSectAddr, void* pMemAddr, int nLength)
{
	BOOL bSuc = 0;
	DWORD dwRet = 0, dwOldProtect = 0;

    
    if(!pSectAddr || !pMemAddr) return false;
    
	bSuc = VirtualProtect( pSectAddr, nLength, PAGE_EXECUTE_READWRITE, &dwOldProtect ); 
    if(!bSuc)
    {
        printf("[%s] pSectAddr=%p, Length=%d vm_protect Failed. 01 \n", __FUNCTION__, pSectAddr, nLength );
        return false;
    }
    
    memset( pSectAddr, NOP, nLength );
    memcpy( pSectAddr, pMemAddr, nLength );
    
	bSuc = VirtualProtect( pSectAddr, nLength, dwOldProtect, NULL ); 
	if(!bSuc)
	{
        printf("[%s] pSectAddr=%p, Length=%d vm_protect Failed. 02 \n", __FUNCTION__, pSectAddr, nLength );
        return false;
    }
    return true;
}



/*
bool CHookCode::WriteJumpCode_Call(PHookData pHookInfo)
{
    bool  bSuc = false;
    PBYTE pPos = NULL;
    void* pFuncAddr = NULL;
    void* pNextAddr = NULL;
    void* pPosAddr  = NULL;
    int   nLength=0, nCopySize=0, nOldSize=0, nHookSize=0;
    char  czHookOPCode[SIZE_CODESECT];
    HDE   HCmd;
    
    if(!pHookInfo) return false;
    
    // HookOPCode Init
    memset( czHookOPCode, NOP, sizeof(czHookOPCode) );
    nHookSize = pHookInfo->nHookSize;
    pFuncAddr = pHookInfo->pBaseAddress;
    pNextAddr = pHookInfo->pNextAddress;
    pPos = (PBYTE)czHookOPCode;
    
    if(!pFuncAddr || !pPos || !pNextAddr || nHookSize <=0)
    {
        return false;
    }
    
    printf("[%s][%s][%s] \n", __FUNCTION__, pHookInfo->pczLibName, pHookInfo->pczFuncName );
    while(nLength < nHookSize)
    {
        pPosAddr = (void*)((ULONG)pFuncAddr + nLength);
        nCopySize = HDE_DISASM( pPosAddr, &HCmd );
        nLength += nCopySize;
        DisplayOPCode( "Old >", pPosAddr, nCopySize );
    }
    
    // Original Backup
    nOldSize = nLength;
    pHookInfo->nOldSize = nOldSize;
    memset( pHookInfo->czOldOPCode, NOP, sizeof(pHookInfo->czOldOPCode) );
    memcpy( pHookInfo->czOldOPCode, pFuncAddr, nOldSize );
    
    bSuc = UpdateNextCommand( pHookInfo );
    if(!bSuc)
    {
        printf( "[%s] UpdateNextCommand failed. \n", __FUNCTION__ );
    }
    
#if defined(__i386__)
    if(pPos)
    {
        pPos[0] = (BYTE)0xE9;
        int* pRVA = (int*)&pPos[1];
        *pRVA = (PBYTE)pHookInfo->pHookAddress - ((PBYTE)pFuncAddr + nHookSize);
    }
    
    pPos = (PBYTE)pHookInfo->pNextAddress + nHookSize - 5;
    if(*pPos == (BYTE)0xE8)
    {
        int nVaddr = 0;
        pPos++;
        nVaddr = (int)((PBYTE)pFuncAddr + nHookSize + (*(int*)pPos));
        *((int*)pPos) = nVaddr - (int)((PBYTE)pHookInfo->pNextAddress + nHookSize);
    }
#elif defined(__x86_64__)
    if(pPos)
    {
        pPos[0] = (BYTE)0x48;
        pPos[1] = (BYTE)0xB8;
        uint64_t* pVaddr = (uint64_t*)&pPos[2];
        *pVaddr = (uint64_t)pHookInfo->pHookAddress;
        pPos[10] = (BYTE)0xFF;
        pPos[11] = (BYTE)0xE0;
    }
#endif
    
    bSuc = CodeSectMemset( pFuncAddr, nOldSize, NOP );
    if(!bSuc) printf("[%s] CodeSectMemory Failed. \n", __FUNCTION__ );
    
    bSuc = CodeSectMemcpy( pFuncAddr, czHookOPCode, nHookSize );
    if(!bSuc) printf("[%s] CodeSectMemcpy Failed. \n", __FUNCTION__ );
    
    return true;
}


bool CHookCode::WriteJumpCode_Return(PHookData pHookInfo)
{
    bool bSuc = false;
    PBYTE pPos = NULL;
    void* pNextAddr = NULL;
    int   nOldSize=0, nHookSize=0, nNextSize=0;
    char  czHookOPCode[SIZE_CODESECT];
    
    if(!pHookInfo) return false;
    
    memset( czHookOPCode, NOP, sizeof(czHookOPCode) );
    nOldSize  = pHookInfo->nOldSize;
    nHookSize = pHookInfo->nHookSize;
    nNextSize = pHookInfo->nNextSize;
    pNextAddr = (void*)((ULONG)pHookInfo->pNextAddress + (ULONG)nNextSize);
    pPos = (PBYTE)czHookOPCode;
    
    if(!pNextAddr || !pPos || nOldSize <= 0 || nHookSize <=0 || nNextSize <= 0)
    {
        return false;
    }
    
#if defined(__i386__)
    if(pPos)
    {
        pPos[0] = (BYTE)0xE9;
        uint32_t* pAddr = (uint32_t*)&pPos[1];
        *pAddr = ((PBYTE)pHookInfo->pBaseAddress + nOldSize) - ((PBYTE)pNextAddr + nHookSize);
    }
#elif defined(__x86_64__)
    if(pPos)
    {
        pPos[0] = (BYTE)0x48;
        pPos[1] = (BYTE)0xB8;
        uint64_t* pAddr = (uint64_t*)&pPos[2];
        *pAddr = (uint64_t)((PBYTE)pHookInfo->pBaseAddress + nOldSize);
        pPos[10] = (BYTE)0xFF;
        pPos[11] = (BYTE)0xE0;
    }
#endif
    
    pHookInfo->nNextSize = nNextSize + nHookSize;
    
    bSuc = CodeSectMemcpy( pNextAddr, czHookOPCode, nHookSize );
    if(!bSuc) printf("[%s] CodeSectMemcpy Failed. \n", __FUNCTION__ );
    
    return true;
}
*/


