


#pragma once

#include "detour.h"



#define DETOUR_TRAMPOLINE_SIZE          32

#define DETOUR_TRAMPOLINE(trampoline,target) \
static PVOID   _detour_get_va_##target(VOID) \
{ \
	return &target; \
} \
	\
__declspec(naked) trampoline \
{ \
	__asm { nop };\
	__asm { nop };\
	__asm { call _detour_get_va_##target };\
	__asm { jmp eax };\
	__asm { ret };\
	__asm { nop };\
	__asm { nop };\
	__asm { nop };\
	__asm { nop };\
	__asm { nop };\
	__asm { nop };\
	__asm { nop };\
	__asm { nop };\
	__asm { nop };\
	__asm { nop };\
	__asm { nop };\
	__asm { nop };\
	__asm { nop };\
	__asm { nop };\
	__asm { nop };\
	__asm { nop };\
	__asm { nop };\
	__asm { nop };\
	__asm { nop };\
	__asm { nop };\
	__asm { nop };\
	__asm { nop };\
}



#define DETOUR_TRAMPOLINE_EMPTY(trampoline , byte1 , byte2) \
__declspec(naked) trampoline \
{ \
	__asm { nop };\
	__asm { nop };\
	__asm { xor eax, eax };\
	__asm { mov eax, [eax] };\
	__asm { ret };\
	__asm { nop };\
	__asm { nop };\
	__asm { nop };\
	__asm { nop };\
	__asm { nop };\
	__asm { nop };\
	__asm { nop };\
	__asm { nop };\
	__asm { nop };\
	__asm { nop };\
	__asm { nop };\
	__asm { nop };\
	__asm { nop };\
	__asm { nop };\
	__asm { nop };\
	__asm { nop };\
	__asm { nop };\
	__asm { nop };\
	__asm { __emit (byte1) };\
	__asm { __emit (byte2) };\
	__asm { nop };\
	__asm { nop };\
	__asm { nop };\
	__asm { nop };\
	__asm { nop };\
}
//////////////////////////////////////////////////////////////////////////
//该接口在驱动层调用会出问题!!!!
NTSTATUS __stdcall hook_function_with_trampoline(pbyte trampoline
										 , pbyte hooker
										 , pbyte*	real_trampoline
										 , pbyte* real_target);

//驱动只能调用这个接口
NTSTATUS __stdcall hook_function_with_empty_trampoline(pbyte trampoline
											 , pbyte target
											 , pbyte hooker
											 , pbyte* real_trampoline
											 , pbyte* real_target
											 , pbyte* real_hooker
											 , long* written);

NTSTATUS __stdcall hook_remove(pbyte trampoline , pbyte hooker);


pbyte __stdcall get_final_code(pbyte code , byte skip_jmp);
