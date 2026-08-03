

#pragma once


typedef unsigned char		byte;
typedef unsigned char		*pbyte;
typedef unsigned long ulong;
typedef char	*pchar;
typedef void	*pvoid;
typedef short	*pshort;
typedef long	*plong;

typedef long NTSTATUS;
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001L)
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L) 
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)

#define DETOUR_INSTRUCTION_TARGET_NONE          ((pbyte)0)
#define DETOUR_INSTRUCTION_TARGET_DYNAMIC   ((pbyte)~0ul)



NTSTATUS __stdcall detour_sanity_check();


//功能
//从src 复制一条指令到dst.
//参数
// dst
//指令的目标地址. 如果只是需要测量一条指令的长度,该参数为NULL.
//如果不为空,那么指令本身以及相关的参数都会被复制.
//src
//指令的源地址.
//target_pptr
//输出一些指令的目标地址. 某些指令有目标地址. 该地址指向另外的
//指令. 比如 call和jump.  该参数可以为NULL
//extra
//输出指令到目标需要扩展的字节数. 比如指令有一个1字节的相关偏移
//但是需要一个4字节的相关偏移.那么extra =3 .
//返回值
//返回src的下一个指令的地址.
//注释
//调用者可以利用target_pptr来跟踪指令流. 但是,有些指令的目标地址
//无法静态分析出来. 比如 一个jump指令的目标地址存储在某个寄存器中.
//这样就无法静态分析出jump的target地址. 在这种情况下,target_pptr有两个
//宏定义来表示
//		DETOUR_INSTRUCTION_TARGET_NONE
//			指令没有目标
//		DETOUR_INSTRUCTION_TARGET_DYNAMIC
//			指令的目标地址是动态的
pbyte __stdcall detour_copy_instruction(pbyte dst , pbyte src , pbyte * target_pptr , long* extra);
//




//////////////////////////////////////////////////////////////////////////


//////////////////////////////////////////////////////////////////////////////
//
inline PBYTE DetourGenMovEax(PBYTE pbCode, UINT32 nValue)
{
	*pbCode++ = 0xB8;
	*((UINT32*&)pbCode)++ = nValue;
	return pbCode;
}

inline PBYTE DetourGenMovEbx(PBYTE pbCode, UINT32 nValue)
{
	*pbCode++ = 0xBB;
	*((UINT32*&)pbCode)++ = nValue;
	return pbCode;
}

inline PBYTE DetourGenMovEcx(PBYTE pbCode, UINT32 nValue)
{
	*pbCode++ = 0xB9;
	*((UINT32*&)pbCode)++ = nValue;
	return pbCode;
}

inline PBYTE DetourGenMovEdx(PBYTE pbCode, UINT32 nValue)
{
	*pbCode++ = 0xBA;
	*((UINT32*&)pbCode)++ = nValue;
	return pbCode;
}

inline PBYTE DetourGenMovEsi(PBYTE pbCode, UINT32 nValue)
{
	*pbCode++ = 0xBE;
	*((UINT32*&)pbCode)++ = nValue;
	return pbCode;
}

inline PBYTE DetourGenMovEdi(PBYTE pbCode, UINT32 nValue)
{
	*pbCode++ = 0xBF;
	*((UINT32*&)pbCode)++ = nValue;
	return pbCode;
}

inline PBYTE DetourGenMovEbp(PBYTE pbCode, UINT32 nValue)
{
	*pbCode++ = 0xBD;
	*((UINT32*&)pbCode)++ = nValue;
	return pbCode;
}

inline PBYTE DetourGenMovEsp(PBYTE pbCode, UINT32 nValue)
{
	*pbCode++ = 0xBC;
	*((UINT32*&)pbCode)++ = nValue;
	return pbCode;
}

inline PBYTE DetourGenPush(PBYTE pbCode, UINT32 nValue)
{
	*pbCode++ = 0x68;
	*((UINT32*&)pbCode)++ = nValue;
	return pbCode;
}

inline PBYTE DetourGenPushad(PBYTE pbCode)
{
	*pbCode++ = 0x60;
	return pbCode;
}

inline PBYTE DetourGenPopad(PBYTE pbCode)
{
	*pbCode++ = 0x61;
	return pbCode;
}

inline PBYTE DetourGenJmp(PBYTE pbCode, PBYTE pbJmpDst, PBYTE pbJmpSrc = 0)
{
	if (pbJmpSrc == 0) {
		pbJmpSrc = pbCode;
	}
	*pbCode++ = 0xE9;
	*((INT32*&)pbCode)++ = pbJmpDst - (pbJmpSrc + 5);
	return pbCode;
}

inline PBYTE DetourGenCall(PBYTE pbCode, PBYTE pbJmpDst, PBYTE pbJmpSrc = 0)
{
	if (pbJmpSrc == 0) {
		pbJmpSrc = pbCode;
	}
	*pbCode++ = 0xE8;
	*((INT32*&)pbCode)++ = pbJmpDst - (pbJmpSrc + 5);
	return pbCode;
}

inline PBYTE DetourGenBreak(PBYTE pbCode)
{
	*pbCode++ = 0xcc;
	return pbCode;
}

inline PBYTE DetourGenRet(PBYTE pbCode)
{
	*pbCode++ = 0xc3;
	return pbCode;
}

inline PBYTE DetourGenNop(PBYTE pbCode)
{
	*pbCode++ = 0x90;
	return pbCode;
}