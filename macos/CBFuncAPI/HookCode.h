
#ifndef _HOOK_CODE_H_
#define _HOOK_CODE_H_

#pragma GCC visibility push(hidden)

#include <iostream>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <pthread.h>
#include <pstdint.h>


#pragma pack(push, 1)

typedef INT8*   PINT8;
typedef INT16*  PINT16;
typedef INT32*  PINT32;
typedef INT64*  PINT64;
typedef UINT8*  PUINT8;
typedef UINT16* PUINT16;
typedef UINT32* PUINT32;
typedef UINT64* PUINT64;
typedef void* PVOID;
typedef unsigned char BYTE, *PBYTE;
typedef unsigned long ULONG, *PULONG;



#define BYTE_ALIGN  16

#if defined(__x86_64__)
    #define SIZE_HOOKCODE 12
    #define SIZE_CODESECT (64 + BYTE_ALIGN)
#elif defined(__i386__)
    #define SIZE_HOOKCODE  5
    #define SIZE_CODESECT (32 + BYTE_ALIGN)
#endif


// Structs for writing x86/x64 instructions.
// 8-bit relative jump.
typedef struct _JMP_REL_SHORT
{
    UINT8  opcode;      // EB xx: JMP +2+xx
    UINT8  operand;
} JMP_REL_SHORT, *PJMP_REL_SHORT;

// 32-bit direct relative jump/call.
typedef struct _JMP_REL
{
    UINT8  opcode;      // E9/E8 xxxxxxxx: JMP/CALL +5+xxxxxxxx
    UINT32 operand;     // Relative destination address
} JMP_REL, *PJMP_REL, CALL_REL;

// 64-bit indirect absolute jump.
typedef struct _JMP_ABS
{
    UINT8  opcode0;     // FF25 00000000: JMP [+6]
    UINT8  opcode1;
    UINT32 dummy;
    UINT64 address;     // Absolute destination address
} JMP_ABS, *PJMP_ABS;

// 64-bit indirect absolute call.
typedef struct _CALL_ABS
{
    UINT8  opcode0;     // FF15 00000002: CALL [+6]
    UINT8  opcode1;
    UINT32 dummy0;
    UINT8  dummy1;      // EB 08:         JMP +10
    UINT8  dummy2;
    UINT64 address;     // Absolute destination address
} CALL_ABS;

// 32-bit direct relative conditional jumps.
typedef struct _JCC_REL
{
    UINT8  opcode0;     // 0F8* xxxxxxxx: J** +6+xxxxxxxx
    UINT8  opcode1;
    UINT32 operand;     // Relative destination address
} JCC_REL;

// 64bit indirect absolute conditional jumps that x64 lacks.
typedef struct _JCC_ABS
{
    UINT8  opcode;      // 7* 0E:         J** +16
    UINT8  dummy0;
    UINT8  dummy1;      // FF25 00000000: JMP [+6]
    UINT8  dummy2;
    UINT32 dummy3;
    UINT64 address;     // Absolute destination address
} JCC_ABS;

//
//
// RIP-Relative Addressing
//
typedef struct _CMD_ABS_7
{
    UINT8  opcode[3];   // 0x48 8B 0D
    UINT32 dummy0;
    UINT8  dummy1;      // EB 08:         JMP +10
    UINT8  dummy2;
    UINT64 address;     // Absolute destination address
} CMD_ABS_7;

typedef struct _CMD_ABS_6
{
    UINT8  opcode[2];   // 8B 0D
    UINT32 dummy0;
    UINT8  dummy1;      // EB 08:         JMP +10
    UINT8  dummy2;
    UINT64 address;     // Absolute destination address
} CMD_ABS_6;

typedef struct _HookData
{
    struct _HookData* pNext;
    bool   bInternNext;
    char*  pczLibName;
    char*  pczFuncName;
    PVOID  pBaseAddress; // 원본 API 주소
    PVOID  pHookAddress; // 후킹 API 주소
    PVOID  pNextAddress; // Next
    UINT32 nOldSize;
    UINT32 nHookSize;
    UINT32 nNextSize;
    BYTE   czOldOPCode[SIZE_CODESECT];
} HookData, *PHookData;
#pragma pack(pop)


class CHookCode
{
public:
    CHookCode();
    ~CHookCode();
public:
    bool Initialize();
    bool Finalize();
    
    bool UnhookAPI( void* pNextAddress );
    bool HookAPI( const char* pczLibName, const char* pczFuncName, void* pHookAddress, void** ppNextAddress);
    bool HookAPI_Code( const char* pczLibName, const char* pczFuncName, void* pHookAddress, void* pNextAddress, int nNextSize );
    
protected:
    void* FetchAddress( const char* pczLibName, const char* pczFuncName );
    void* FetchMachAddress( const char* pczLibName, const char* pczFuncName );
    void DisplayOPCode(const char* pczTitle, void* pAddress, int nLength );
    
    bool UpdateNextCommand( PHookData pHookInfo );
    bool WriteJump_Call(PHookData pHookInfo);
    bool WriteJump_Return(PHookData pHookInfo);
    bool HookAPI_Int( const char* pczLibName, const char* pczFuncName, void* pHookAddress, void** ppNextAddress );
    bool HookAPI_CodeInt(const char* pczLibName, const char* pczFuncName, void* pHookAddress, void* pNextAddress, int nNextSize );
    
protected:
    void HookData_free( PHookData pHookInfo );
    PHookData HookData_malloc( const char* pczLibName, const char* pczFuncName );
    PHookData HookData_Search( PVOID pNextAddress );
    PHookData HookData_Search( const char* pczLibName, const char* pczFuncName );
    bool HookData_Append( PHookData pHookInfo );
    bool HookData_Delete( PVOID pNextAddress );
    void HookData_DeleteAll();
    
public:
    bool CodeSectInit();
    void* CodeSectAlloc();
    void CodeSectFree(void* pSectAddr);
    bool CodeSectMemset(void* pSectAddr, int nLength, BYTE cValue);
    bool CodeSectMemcpy(void* pSectAddr, void* pMemAddr, int nLength);
    int GetCodeSectPos();
    int GetCodeSectMaxPos();
    int GetCodeSectLength();
    
private:
    INT32  m_nPos;
    INT32  m_nMaxPos;
    INT32  m_nMaxLength;
    HookData* m_pHead;
    pthread_mutex_t m_MutexHook;

public:
    //
    // bool WriteJumpCode_Call(PHookData pHookInfo);
    // bool WriteJumpCode_Return(PHookData pHookInfo);
    //


    
};


extern CHookCode g_Hook;



#pragma GCC visibility pop

#endif /* _HOOK_CODE_H_ */
