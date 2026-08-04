


#include "stdafx.h"

#define ENV_APPLICATION
#include "inline_hook.h"


#ifdef ENV_APPLICATION
void enable_write_on_code_page(pbyte code , long cb , ulong* old_perm)
{
	if(code && cb)
	{
		if(!::FlushInstructionCache(::GetCurrentProcess()
			, code , cb))
			return ;
	}

	::VirtualProtect(code , cb , PAGE_EXECUTE_READWRITE , old_perm);
}

void disable_write_on_code_page(pbyte code , long cb , ulong perm)
{
	ulong old_perm = 0;
	if(perm && code && cb)
		if(!::FlushInstructionCache(::GetCurrentProcess() , code , cb))
			return ;

	::VirtualProtect(code , cb , perm , &old_perm);
}

#define DBG_OUT 
#else
#define DBG_OUT DbgPrint
#endif

//////////////////////////////////////////////////////////////////////////
enum operand_code
{
	OP_PRE_ES       = 0x26,
	OP_PRE_CS       = 0x2e,
	OP_PRE_SS       = 0x36,
	OP_PRE_DS       = 0x3e,
	OP_PRE_FS       = 0x64,
	OP_PRE_GS       = 0x65,
	OP_JMP_SEG      = 0x25,

	OP_JA           = 0x77,
	OP_NOP          = 0x90,
	OP_CALL         = 0xe8,
	OP_JMP          = 0xe9,
	OP_PREFIX       = 0xff,
	OP_MOV_EAX      = 0xa1,
	OP_SET_EAX      = 0xb8,
	OP_JMP_EAX      = 0xe0,
	OP_RET_POP      = 0xc2,
	OP_RET          = 0xc3,
	OP_BRK          = 0xcc,

	SIZE_OF_JMP     = 5,
	SIZE_OF_NOP     = 1,
	SIZE_OF_BRK     = 1,
	SIZE_OF_TRP_OPS = SIZE_OF_JMP /* + SIZE_OF_BRK */,
};

__inline pbyte gen_jmp(pbyte code , pbyte jmp_dst , pbyte jmp_src)
{
	if(jmp_src == 0)
		jmp_src = code;

	*code++ = 0xE9;
	*(long*)code = jmp_dst - jmp_src - 5;
	code += sizeof(long) ;
	return code;
}

__inline pbyte gen_call(pbyte code , pbyte call_dst , pbyte call_src)
{
	if(call_src == 0)
		call_src = code;
	*code++ = 0xE8;
	*(long*)code = call_dst - call_src - 5;
	code += sizeof(long);
	return code;
}

__inline pbyte gen_break(pbyte code)
{
	*code++ = 0xcc;
	return code;
}

__inline pbyte gen_ret(pbyte code)
{
	*code++ = 0xc3;
	return code;
}

__inline pbyte gen_nop(pbyte code)
{
	*code++ = 0x90;
	return code;
}


pbyte __stdcall get_final_code(pbyte code , byte skip_jmp)
{
	if(code == NULL)
		return NULL;

	if(code[0] == OP_PREFIX
		&& code[1] == OP_JMP_SEG)
	{
		code = *((pbyte*) &code[2]);
		code = *((pbyte*)code);
	}
	else if(code[0] == OP_JMP 
		&& skip_jmp)
		code = code + SIZE_OF_JMP + *((long*)&code[1]);

	return code;
}

NTSTATUS __stdcall insert_jump(pbyte code , pbyte dst , long length)
{
	if(length < SIZE_OF_JMP)
		return STATUS_UNSUCCESSFUL;

	code = gen_jmp(code , dst , 0);
	for(length -= SIZE_OF_JMP ; length > 0 ; length--)
		code = gen_nop(code);

	return STATUS_SUCCESS;
}

NTSTATUS __stdcall insert_detour(pbyte target 
							  , pbyte trampoline
							  , pbyte hooker
							  , long* written)
{
	pbyte cont = target;
	long target_length = 0;
	if (written)
		*written = 0;
	//确定目标函数是否能容纳一个jmp指令的空间.
	for(; target_length < SIZE_OF_TRP_OPS ;)
	{
		pbyte	op = cont;
		byte		op_code = *op;
		cont = detour_copy_instruction(NULL , cont , NULL , NULL);
		target_length = cont - target;

		if(op_code == OP_JMP
			|| op_code == OP_JMP_EAX
			|| op_code == OP_RET_POP
			|| op_code == OP_RET)
			break;

		if(op_code == OP_PREFIX 
			&& op[1] == OP_JMP_SEG)
			break;

		if(	(op_code  == OP_PRE_ES
			|| op_code == OP_PRE_CS
			|| op_code == OP_PRE_SS
			|| op_code == OP_PRE_DS
			|| op_code == OP_PRE_FS
			|| op_code == OP_PRE_GS)
			&& op[1] == OP_PREFIX
			&& op[2] == OP_JMP_SEG)
			break;
	}
	
	if((target_length < SIZE_OF_TRP_OPS) 
		|| (target_length > (DETOUR_TRAMPOLINE_SIZE - SIZE_OF_JMP -1)))
		return STATUS_UNSUCCESSFUL;
	else
	{
		pbyte src = target;
		pbyte dst = trampoline;
		long copy_bytes = 0;
#ifdef ENV_APPLICATION
		ulong trampoline_perm = 0, target_perm = 0;
		enable_write_on_code_page(trampoline , DETOUR_TRAMPOLINE_SIZE
			, &trampoline_perm);
		enable_write_on_code_page(target , target_length , &target_perm);
#endif
		//将目标函数要替换的指令保存在trampoline函数内.
		for( ; copy_bytes < target_length ; )
		{
			src = detour_copy_instruction(dst , src , NULL , NULL);
			copy_bytes = src - target;
			dst = trampoline + copy_bytes;
		}

		if(copy_bytes != target_length)
			return STATUS_UNSUCCESSFUL;

		if (written)
			*written = copy_bytes;

		//在trampoline函数接一个跳转指令,
		//跳转到目标函数未替换的第一个指令
		if(!NT_SUCCESS(insert_jump(dst , target + copy_bytes , SIZE_OF_JMP)))
			return STATUS_UNSUCCESSFUL;
		
		//在trampoline函数末尾写入替换的指令长度.(用于还原和检查)
		trampoline[DETOUR_TRAMPOLINE_SIZE - 1] = (byte)copy_bytes;
		
		//在目标函数头部写入跳转指令,跳转到hooker函数
		if(!NT_SUCCESS(insert_jump(target , hooker , copy_bytes)))
			return STATUS_UNSUCCESSFUL;

#ifdef ENV_APPLICATION
		disable_write_on_code_page(trampoline , DETOUR_TRAMPOLINE_SIZE , trampoline_perm);
		disable_write_on_code_page(target , target_length , target_perm);
#endif 

		return STATUS_SUCCESS;

	}
}

NTSTATUS __stdcall hook_remove(pbyte trampoline , pbyte hooker)
{
	long target_length , offset;
	pbyte target , target_detour;
	trampoline = get_final_code(trampoline , TRUE);
	hooker = get_final_code(hooker , FALSE);

	target_length = trampoline[DETOUR_TRAMPOLINE_SIZE - 1];
	if(target_length == 0 || target_length >= DETOUR_TRAMPOLINE_SIZE -1)
	{
		DBG_OUT("detour : trampoline func is invalid.\r\n");
		return STATUS_UNSUCCESSFUL;
	}

	if(trampoline[target_length] != OP_JMP)
	{
		DBG_OUT("detour : trampoline func is invalid.\r\n");
		return STATUS_UNSUCCESSFUL;
	}

	offset = *((long*)&trampoline[target_length + 1]);
	target = trampoline + target_length + SIZE_OF_JMP + offset - target_length;

	if(target[0] != OP_JMP)
	{
		DBG_OUT("detour : target func is invalid.\r\n");
		return STATUS_UNSUCCESSFUL;
	}

	offset = *((long*)&target[1]);
	target_detour = target + SIZE_OF_JMP + offset;
	if(target_detour != hooker)
	{
		DBG_OUT("detour : target func is invalid.\r\n");
		return STATUS_UNSUCCESSFUL;
	}

	//////////////////////////////////////////////////////////////////////////
	if(TRUE)
	{
		pbyte src = trampoline;
		pbyte dst = target;
		long copy_bytes = 0;

#ifdef ENV_APPLICATION
		ulong mem_perm = 0;
		enable_write_on_code_page(target , target_length , &mem_perm);
#endif

		for(; copy_bytes < target_length ; dst = target + copy_bytes)
		{
			src = detour_copy_instruction(dst , src , NULL , NULL);
			copy_bytes = src - trampoline;
		}

#ifdef ENV_APPLICATION
		disable_write_on_code_page(target , target_length , mem_perm);
#endif

		if(copy_bytes != target_length)
		{
			DBG_OUT("detour : remove detour faild.\r\n");
			return STATUS_UNSUCCESSFUL;
		}
	}

	return STATUS_SUCCESS;

}


NTSTATUS __stdcall hook_function_with_trampoline(pbyte trampoline
										 , pbyte hooker
										 , pbyte*	real_trampoline
										 , pbyte* real_target)
{
	pvoid (* get_target_address)();

	pbyte target = NULL;
	trampoline = get_final_code(trampoline , TRUE);
	hooker = get_final_code(hooker , FALSE);

	if(real_trampoline)
		*real_trampoline = trampoline;
	if(real_target)
		*real_target = NULL;

	if(trampoline == NULL || hooker == NULL)
		return STATUS_UNSUCCESSFUL;

	if(trampoline[0] != OP_NOP
		|| trampoline[1] != OP_NOP
		|| trampoline[2] != OP_CALL
		|| trampoline[7] != OP_PREFIX
		|| trampoline[8] != OP_JMP_EAX	) 
		return STATUS_UNSUCCESSFUL;

	get_target_address = (pvoid ( *)())(trampoline + SIZE_OF_NOP 
		+ SIZE_OF_NOP + SIZE_OF_JMP + *(long*)&trampoline[3]);

	target = get_final_code((pbyte)(*get_target_address)() , FALSE);

	if(real_target)
		*real_target = target;

	return insert_detour(target , trampoline , hooker, 0);
}


NTSTATUS __stdcall hook_function_with_empty_trampoline(pbyte trampoline
											 , pbyte target
											 , pbyte hooker
											 , pbyte* real_trampoline
											 , pbyte* real_target
											 , pbyte* real_hooker
											 , long* written)
{
	trampoline = get_final_code(trampoline , TRUE);
	target = get_final_code(target , FALSE);
	hooker = get_final_code(hooker , FALSE);
	if (written) *written = 0;

	if(real_trampoline)
		*real_trampoline = trampoline;
	if(real_target)
		*real_target = target;
	if(real_hooker)
		*real_hooker = hooker;

	if(trampoline == NULL 
		|| target == NULL
		|| hooker == NULL)
		return STATUS_UNSUCCESSFUL;

	//if(trampoline[0] != OP_NOP || trampoline[1] != OP_NOP)
	//	return STATUS_UNSUCCESSFUL;

	return insert_detour(target , trampoline , hooker, written);
}


