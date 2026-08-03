//////////////////////////////////////////////////////////////////////////
//#define ENV_APPLICATION

#include "stdafx.h"
#include "detour.h"


#define DBG_OUT 


enum 
{
	mod_offset_dynamic 	= 0x1u,
	mod_offset_address 	= 0x2u,
	mod_offset_noenlarge	= 0x4u,

	mod_offset_sib				= 0x10u,
	mod_offset_notsib		= 0x0fu,
};


typedef struct instruction_copy_params
{
	byte			is_16bit_operand;
	byte			is_16bit_address;

	pbyte*		target_pptr;
	long*		extra_ptr;

	long		scratch_extra;
	pbyte		scratch_target;
	byte			scratch_dst[64];
} icp;


struct instruction_copy_entry;

typedef const struct instruction_copy_entry *ref_ice;

typedef pbyte (__stdcall * instruction_copy_func)(ref_ice entry
												  , pbyte dst
												  , pbyte src
												  , icp* cp);


typedef struct instruction_copy_entry 
{
	ulong 		op_code 		: 8;						// Opcode
	ulong		fix_size 			: 3;						// Fixed size of opcode
	ulong		fix_size16 		: 3;						// Fixed size when 16 bit operand
	ulong		mod_offset 	: 3;						// Offset to mod/rm byte (0=none)
	long		rel_offset 		: 3;						// Offset to relative target.
	ulong		flags				: 4;						// Flags for mod_offset_dynamic, etc.
	instruction_copy_func	copy_fun;			// Function pointer.
} ice ;





//////////////////////////////////////////////////////////////////////////
pbyte __stdcall adjust_target(pbyte dst , pbyte src , long op , long target_offset , icp* cp);

pbyte __stdcall  copy_invalid(ref_ice entry , pbyte dst , pbyte src , icp* cp);

pbyte  __stdcall copy_bytes(ref_ice entry , pbyte dst , pbyte src , icp* cp);

pbyte  __stdcall copy_bytes_prefix(ref_ice entry , pbyte dst , pbyte src , icp *cp);
////////////////////////////////////////////////////// Individual Bytes Codes.
pbyte  __stdcall copy_0f(ref_ice entry , pbyte dst , pbyte src , icp *cp);

pbyte  __stdcall copy_66(ref_ice entry , pbyte dst , pbyte src , icp *cp);

pbyte __stdcall  copy_67(ref_ice entry , pbyte dst , pbyte src , icp *cp);

pbyte  __stdcall copy_F6(ref_ice entry , pbyte dst , pbyte src , icp *cp);

pbyte  __stdcall copy_F7(ref_ice entry , pbyte dst , pbyte src , icp * cp);

pbyte  __stdcall copy_FF(ref_ice entry , pbyte dst , pbyte src , icp * cp);
//////////////////////////////////////////////////////////////////////////

#define entry_copy_bytes1								1, 1, 0, 0, 0, copy_bytes
#define entry_copy_bytes1_dynamic				1, 1, 0, 0, mod_offset_dynamic,copy_bytes
#define entry_copy_bytes2								2, 2, 0, 0, 0, copy_bytes
#define entry_copy_bytes2_jump					2, 2, 0, 1, 0, copy_bytes
#define entry_copy_bytes2_cant_jump			2, 2, 0, 1, mod_offset_noenlarge, copy_bytes
#define entry_copy_bytes2_dynamic				2, 2, 0, 0, mod_offset_dynamic, copy_bytes
#define entry_copy_bytes3								3, 3, 0, 0, 0, copy_bytes
#define entry_copy_bytes3_dynamic				3, 3, 0, 0, mod_offset_dynamic,copy_bytes
#define entry_copy_bytes3_or_5						5, 3, 0, 0, 0, copy_bytes
#define entry_copy_bytes3_or_5target			5, 3, 0, 1, 0, copy_bytes
#define entry_copy_bytes5_or_7dynamic		7, 5, 0, 0, mod_offset_dynamic, copy_bytes
#define entry_copy_bytes3_or_5address		5, 3, 0, 0, mod_offset_address, copy_bytes
#define entry_copy_bytes4								4, 4, 0, 0, 0, copy_bytes
#define entry_copy_bytes5								5, 5, 0, 0, 0, copy_bytes
#define entry_copy_bytes7								7, 7, 0, 0, 0, copy_bytes
#define entry_copy_bytes2_mod					2, 2, 1, 0, 0, copy_bytes
#define entry_copy_bytes2_mod1					3, 3, 1, 0, 0, copy_bytes
#define entry_copy_bytes2_mod_operand	6, 4, 1, 0, 0, copy_bytes
#define entry_copy_bytes3_mod					3, 3, 2, 0, 0, copy_bytes
#define entry_copy_bytes_prefix					1, 1, 0, 0, 0, copy_bytes_prefix
#define entry_copy_0f										1, 1, 0, 0, 0, copy_0f
#define entry_copy_66										1, 1, 0, 0, 0, copy_66
#define entry_copy_67										1, 1, 0, 0, 0, copy_67
#define entry_copy_f6										0, 0, 0, 0, 0, copy_F6
#define entry_copy_f7										0, 0, 0, 0, 0, copy_F7
#define entry_copy_ff										0, 0, 0, 0, 0, copy_FF
#define entry_copy_invalid								1, 1, 0, 0, 0, copy_invalid
#define entry_end												0, 0, 0, 0, 0, 0


//disassembler tables
const byte rb_mod_rm[256] = {
	0,0,0,0, mod_offset_sib|1,4,0,0, 0,0,0,0, mod_offset_sib|1,4,0,0,					// 0x
	0,0,0,0, mod_offset_sib|1,4,0,0, 0,0,0,0, mod_offset_sib|1,4,0,0,					// 1x
	0,0,0,0, mod_offset_sib|1,4,0,0, 0,0,0,0, mod_offset_sib|1,4,0,0,					// 2x
	0,0,0,0, mod_offset_sib|1,4,0,0, 0,0,0,0, mod_offset_sib|1,4,0,0,					// 3x
	1,1,1,1, 2,1,1,1, 1,1,1,1, 2,1,1,1,					// 4x
	1,1,1,1, 2,1,1,1, 1,1,1,1, 2,1,1,1,					// 5x
	1,1,1,1, 2,1,1,1, 1,1,1,1, 2,1,1,1,					// 6x
	1,1,1,1, 2,1,1,1, 1,1,1,1, 2,1,1,1,					// 7x
	4,4,4,4, 5,4,4,4, 4,4,4,4, 5,4,4,4,					// 8x
	4,4,4,4, 5,4,4,4, 4,4,4,4, 5,4,4,4,					// 9x
	4,4,4,4, 5,4,4,4, 4,4,4,4, 5,4,4,4,					// Ax
	4,4,4,4, 5,4,4,4, 4,4,4,4, 5,4,4,4,					// Bx
	0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,					// Cx
	0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,					// Dx
	0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,					// Ex
	0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0					// Fx
};

const struct instruction_copy_entry rce_copy_table[257] =
{ 
	{ 0x00, entry_copy_bytes2_mod },						// ADD /r
	{ 0x01, entry_copy_bytes2_mod },						// ADD /r
	{ 0x02, entry_copy_bytes2_mod },						// ADD /r
	{ 0x03, entry_copy_bytes2_mod },						// ADD /r
	{ 0x04, entry_copy_bytes2 },							// ADD ib
	{ 0x05, entry_copy_bytes3_or_5 },						// ADD iw
	{ 0x06, entry_copy_bytes1 },							// PUSH
	{ 0x07, entry_copy_bytes1 },							// POP
	{ 0x08, entry_copy_bytes2_mod },						// OR /r
	{ 0x09, entry_copy_bytes2_mod },						// OR /r
	{ 0x0A, entry_copy_bytes2_mod },						// OR /r
	{ 0x0B, entry_copy_bytes2_mod },						// OR /r
	{ 0x0C, entry_copy_bytes2 },							// OR ib
	{ 0x0D, entry_copy_bytes3_or_5 },						// OR iw
	{ 0x0E, entry_copy_bytes1 },							// PUSH
	{ 0x0F, entry_copy_0f },								// Extension Ops 
	{ 0x10, entry_copy_bytes2_mod },						// ADC /r
	{ 0x11, entry_copy_bytes2_mod },						// ADC /r
	{ 0x12, entry_copy_bytes2_mod },						// ADC /r
	{ 0x13, entry_copy_bytes2_mod },						// ADC /r
	{ 0x14, entry_copy_bytes2 },							// ADC ib
	{ 0x15, entry_copy_bytes3_or_5 },						// ADC id
	{ 0x16, entry_copy_bytes1 },							// PUSH
	{ 0x17, entry_copy_bytes1 },							// POP
	{ 0x18, entry_copy_bytes2_mod },						// SBB /r
	{ 0x19, entry_copy_bytes2_mod },						// SBB /r
	{ 0x1A, entry_copy_bytes2_mod },						// SBB /r
	{ 0x1B, entry_copy_bytes2_mod },						// SBB /r
	{ 0x1C, entry_copy_bytes2 },							// SBB ib
	{ 0x1D, entry_copy_bytes3_or_5 },						// SBB id
	{ 0x1E, entry_copy_bytes1 },							// PUSH
	{ 0x1F, entry_copy_bytes1 },							// POP
	{ 0x20, entry_copy_bytes2_mod },						// AND /r
	{ 0x21, entry_copy_bytes2_mod },						// AND /r
	{ 0x22, entry_copy_bytes2_mod },						// AND /r
	{ 0x23, entry_copy_bytes2_mod },						// AND /r
	{ 0x24, entry_copy_bytes2 },							// AND ib
	{ 0x25, entry_copy_bytes3_or_5 },						// AND id
	{ 0x26, entry_copy_bytes_prefix },					// ES prefix 
	{ 0x27, entry_copy_bytes1 },							// DAA
	{ 0x28, entry_copy_bytes2_mod },						// SUB /r
	{ 0x29, entry_copy_bytes2_mod },						// SUB /r
	{ 0x2A, entry_copy_bytes2_mod },						// SUB /r
	{ 0x2B, entry_copy_bytes2_mod },						// SUB /r
	{ 0x2C, entry_copy_bytes2 },							// SUB ib
	{ 0x2D, entry_copy_bytes3_or_5 },						// SUB id
	{ 0x2E, entry_copy_bytes_prefix },					// CS prefix 
	{ 0x2F, entry_copy_bytes1 },							// DAS
	{ 0x30, entry_copy_bytes2_mod },						// XOR /r
	{ 0x31, entry_copy_bytes2_mod },						// XOR /r
	{ 0x32, entry_copy_bytes2_mod },						// XOR /r
	{ 0x33, entry_copy_bytes2_mod },						// XOR /r
	{ 0x34, entry_copy_bytes2 },							// XOR ib
	{ 0x35, entry_copy_bytes3_or_5 },						// XOR id
	{ 0x36, entry_copy_bytes_prefix },					// SS prefix 
	{ 0x37, entry_copy_bytes1 },							// AAA
	{ 0x38, entry_copy_bytes2_mod },						// CMP /r
	{ 0x39, entry_copy_bytes2_mod },						// CMP /r
	{ 0x3A, entry_copy_bytes2_mod },						// CMP /r
	{ 0x3B, entry_copy_bytes2_mod },						// CMP /r
	{ 0x3C, entry_copy_bytes2 },							// CMP ib
	{ 0x3D, entry_copy_bytes3_or_5 },						// CMP id
	{ 0x3E, entry_copy_bytes_prefix },					// DS prefix 
	{ 0x3F, entry_copy_bytes1 },							// AAS
	{ 0x40, entry_copy_bytes1 },							// INC
	{ 0x41, entry_copy_bytes1 },							// INC
	{ 0x42, entry_copy_bytes1 },							// INC
	{ 0x43, entry_copy_bytes1 },							// INC
	{ 0x44, entry_copy_bytes1 },							// INC
	{ 0x45, entry_copy_bytes1 },							// INC
	{ 0x46, entry_copy_bytes1 },							// INC
	{ 0x47, entry_copy_bytes1 },							// INC
	{ 0x48, entry_copy_bytes1 },							// DEC
	{ 0x49, entry_copy_bytes1 },							// DEC
	{ 0x4A, entry_copy_bytes1 },							// DEC
	{ 0x4B, entry_copy_bytes1 },							// DEC
	{ 0x4C, entry_copy_bytes1 },							// DEC
	{ 0x4D, entry_copy_bytes1 },							// DEC
	{ 0x4E, entry_copy_bytes1 },							// DEC
	{ 0x4F, entry_copy_bytes1 },							// DEC
	{ 0x50, entry_copy_bytes1 },							// PUSH
	{ 0x51, entry_copy_bytes1 },							// PUSH
	{ 0x52, entry_copy_bytes1 },							// PUSH
	{ 0x53, entry_copy_bytes1 },							// PUSH
	{ 0x54, entry_copy_bytes1 },							// PUSH
	{ 0x55, entry_copy_bytes1 },							// PUSH
	{ 0x56, entry_copy_bytes1 },							// PUSH
	{ 0x57, entry_copy_bytes1 },							// PUSH
	{ 0x58, entry_copy_bytes1 },							// POP
	{ 0x59, entry_copy_bytes1 },							// POP
	{ 0x5A, entry_copy_bytes1 },							// POP
	{ 0x5B, entry_copy_bytes1 },							// POP
	{ 0x5C, entry_copy_bytes1 },							// POP
	{ 0x5D, entry_copy_bytes1 },							// POP
	{ 0x5E, entry_copy_bytes1 },							// POP
	{ 0x5F, entry_copy_bytes1 },							// POP
	{ 0x60, entry_copy_bytes1 },							// PUSHAD
	{ 0x61, entry_copy_bytes1 },							// POPAD
	{ 0x62, entry_copy_bytes2_mod },						// BOUND /r
	{ 0x63, entry_copy_bytes2_mod },						// ARPL /r
	{ 0x64, entry_copy_bytes_prefix },					// FS prefix 
	{ 0x65, entry_copy_bytes_prefix },					// GS prefix 
	{ 0x66, entry_copy_66 },								// Operand Prefix 
	{ 0x67, entry_copy_67 },								// Address Prefix 
	{ 0x68, entry_copy_bytes3_or_5 },						// PUSH
	{ 0x69, entry_copy_bytes2_mod_operand },				// 
	{ 0x6A, entry_copy_bytes2 },							// PUSH
	{ 0x6B, entry_copy_bytes2_mod1 },						// IMUL /r ib 
	{ 0x6C, entry_copy_bytes1 },							// INS
	{ 0x6D, entry_copy_bytes1 },							// INS
	{ 0x6E, entry_copy_bytes1 },							// OUTS/OUTSB
	{ 0x6F, entry_copy_bytes1 },							// OUTS/OUTSW
	{ 0x70, entry_copy_bytes2_jump },						// JO
	{ 0x71, entry_copy_bytes2_jump },						// JNO
	{ 0x72, entry_copy_bytes2_jump },						// JB/JC/JNAE
	{ 0x73, entry_copy_bytes2_jump },						// JAE/JNB/JNC
	{ 0x74, entry_copy_bytes2_jump },						// JE/JZ
	{ 0x75, entry_copy_bytes2_jump },						// JNE/JNZ
	{ 0x76, entry_copy_bytes2_jump },						// JBE/JNA
	{ 0x77, entry_copy_bytes2_jump },						// JA/JNBE
	{ 0x78, entry_copy_bytes2_jump },						// JS
	{ 0x79, entry_copy_bytes2_jump },						// JNS
	{ 0x7A, entry_copy_bytes2_jump },						// JP/JPE
	{ 0x7B, entry_copy_bytes2_jump },						// JNP/JPO
	{ 0x7C, entry_copy_bytes2_jump },						// JL/JNGE
	{ 0x7D, entry_copy_bytes2_jump },						// JGE/JNL
	{ 0x7E, entry_copy_bytes2_jump },						// JLE/JNG
	{ 0x7F, entry_copy_bytes2_jump },						// JG/JNLE
	{ 0x80, entry_copy_bytes2_mod1 },						// ADC/2 ib, etc.s 
	{ 0x81, entry_copy_bytes2_mod_operand },				// 
	{ 0x82, entry_copy_bytes2 },							// MOV al,x
	{ 0x83, entry_copy_bytes2_mod1 },						// ADC/2 ib, etc. 
	{ 0x84, entry_copy_bytes2_mod },						// TEST /r
	{ 0x85, entry_copy_bytes2_mod },						// TEST /r
	{ 0x86, entry_copy_bytes2_mod },						// XCHG /r @todo 
	{ 0x87, entry_copy_bytes2_mod },						// XCHG /r @todo 
	{ 0x88, entry_copy_bytes2_mod },						// MOV /r
	{ 0x89, entry_copy_bytes2_mod },						// MOV /r
	{ 0x8A, entry_copy_bytes2_mod },						// MOV /r
	{ 0x8B, entry_copy_bytes2_mod },						// MOV /r
	{ 0x8C, entry_copy_bytes2_mod },						// MOV /r
	{ 0x8D, entry_copy_bytes2_mod },						// LEA /r
	{ 0x8E, entry_copy_bytes2_mod },						// MOV /r
	{ 0x8F, entry_copy_bytes2_mod },						// POP /0
	{ 0x90, entry_copy_bytes1 },							// NOP
	{ 0x91, entry_copy_bytes1 },							// XCHG
	{ 0x92, entry_copy_bytes1 },							// XCHG
	{ 0x93, entry_copy_bytes1 },							// XCHG
	{ 0x94, entry_copy_bytes1 },							// XCHG
	{ 0x95, entry_copy_bytes1 },							// XCHG
	{ 0x96, entry_copy_bytes1 },							// XCHG
	{ 0x97, entry_copy_bytes1 },							// XCHG
	{ 0x98, entry_copy_bytes1 },							// CWDE
	{ 0x99, entry_copy_bytes1 },							// CDQ
	{ 0x9A, entry_copy_bytes5_or_7dynamic },				// CALL cp 
	{ 0x9B, entry_copy_bytes1 },							// WAIT/FWAIT
	{ 0x9C, entry_copy_bytes1 },							// PUSHFD
	{ 0x9D, entry_copy_bytes1 },							// POPFD
	{ 0x9E, entry_copy_bytes1 },							// SAHF
	{ 0x9F, entry_copy_bytes1 },							// LAHF
	{ 0xA0, entry_copy_bytes3_or_5address },				// MOV
	{ 0xA1, entry_copy_bytes3_or_5address },				// MOV
	{ 0xA2, entry_copy_bytes3_or_5address },				// MOV
	{ 0xA3, entry_copy_bytes3_or_5address },				// MOV
	{ 0xA4, entry_copy_bytes1 },							// MOVS
	{ 0xA5, entry_copy_bytes1 },							// MOVS/MOVSD
	{ 0xA6, entry_copy_bytes1 },							// CMPS/CMPSB
	{ 0xA7, entry_copy_bytes1 },							// CMPS/CMPSW
	{ 0xA8, entry_copy_bytes2 },							// TEST
	{ 0xA9, entry_copy_bytes3_or_5 },						// TEST
	{ 0xAA, entry_copy_bytes1 },							// STOS/STOSB
	{ 0xAB, entry_copy_bytes1 },							// STOS/STOSW
	{ 0xAC, entry_copy_bytes1 },							// LODS/LODSB
	{ 0xAD, entry_copy_bytes1 },							// LODS/LODSW
	{ 0xAE, entry_copy_bytes1 },							// SCAS/SCASB
	{ 0xAF, entry_copy_bytes1 },							// SCAS/SCASD
	{ 0xB0, entry_copy_bytes2 },							// MOV B0+rb
	{ 0xB1, entry_copy_bytes2 },							// MOV B0+rb
	{ 0xB2, entry_copy_bytes2 },							// MOV B0+rb
	{ 0xB3, entry_copy_bytes2 },							// MOV B0+rb
	{ 0xB4, entry_copy_bytes2 },							// MOV B0+rb
	{ 0xB5, entry_copy_bytes2 },							// MOV B0+rb
	{ 0xB6, entry_copy_bytes2 },							// MOV B0+rb
	{ 0xB7, entry_copy_bytes2 },							// MOV B0+rb
	{ 0xB8, entry_copy_bytes3_or_5 },						// MOV B8+rb
	{ 0xB9, entry_copy_bytes3_or_5 },						// MOV B8+rb
	{ 0xBA, entry_copy_bytes3_or_5 },						// MOV B8+rb
	{ 0xBB, entry_copy_bytes3_or_5 },						// MOV B8+rb
	{ 0xBC, entry_copy_bytes3_or_5 },						// MOV B8+rb
	{ 0xBD, entry_copy_bytes3_or_5 },						// MOV B8+rb
	{ 0xBE, entry_copy_bytes3_or_5 },						// MOV B8+rb
	{ 0xBF, entry_copy_bytes3_or_5 },						// MOV B8+rb
	{ 0xC0, entry_copy_bytes2_mod1 },						// RCL/2 ib, etc. 
	{ 0xC1, entry_copy_bytes2_mod1 },						// RCL/2 ib, etc. 
	{ 0xC2, entry_copy_bytes3 },							// RET
	{ 0xC3, entry_copy_bytes1 },							// RET
	{ 0xC4, entry_copy_bytes2_mod },						// LES
	{ 0xC5, entry_copy_bytes2_mod },						// LDS
	{ 0xC6, entry_copy_bytes2_mod1 },						// MOV 
	{ 0xC7, entry_copy_bytes2_mod_operand },				// MOV
	{ 0xC8, entry_copy_bytes4 },							// ENTER
	{ 0xC9, entry_copy_bytes1 },							// LEAVE
	{ 0xCA, entry_copy_bytes3_dynamic },					// RET
	{ 0xCB, entry_copy_bytes1_dynamic },					// RET
	{ 0xCC, entry_copy_bytes1_dynamic },					// INT 3
	{ 0xCD, entry_copy_bytes2_dynamic },					// INT ib
	{ 0xCE, entry_copy_bytes1_dynamic },					// INTO
	{ 0xCF, entry_copy_bytes1_dynamic },					// IRET
	{ 0xD0, entry_copy_bytes2_mod },						// RCL/2, etc.
	{ 0xD1, entry_copy_bytes2_mod },						// RCL/2, etc.
	{ 0xD2, entry_copy_bytes2_mod },						// RCL/2, etc.
	{ 0xD3, entry_copy_bytes2_mod },						// RCL/2, etc.
	{ 0xD4, entry_copy_bytes2 },							// AAM
	{ 0xD5, entry_copy_bytes2 },							// AAD
	{ 0xD6, entry_copy_invalid },							// 
	{ 0xD7, entry_copy_bytes1 },							// XLAT/XLATB
	{ 0xD8, entry_copy_bytes2_mod },						// FADD, etc. 
	{ 0xD9, entry_copy_bytes2_mod },						// F2XM1, etc.
	{ 0xDA, entry_copy_bytes2_mod },						// FLADD, etc. 
	{ 0xDB, entry_copy_bytes2_mod },						// FCLEX, etc. 
	{ 0xDC, entry_copy_bytes2_mod },						// FADD/0, etc. 
	{ 0xDD, entry_copy_bytes2_mod },						// FFREE, etc. 
	{ 0xDE, entry_copy_bytes2_mod },						// FADDP, etc. 
	{ 0xDF, entry_copy_bytes2_mod },						// FBLD/4, etc. 
	{ 0xE0, entry_copy_bytes2_cant_jump },					// LOOPNE cb
	{ 0xE1, entry_copy_bytes2_cant_jump },					// LOOPE cb
	{ 0xE2, entry_copy_bytes2_cant_jump },					// LOOP cb
	{ 0xE3, entry_copy_bytes2_jump },						// JCXZ/JECXZ
	{ 0xE4, entry_copy_bytes2 },							// IN ib
	{ 0xE5, entry_copy_bytes2 },							// IN id
	{ 0xE6, entry_copy_bytes2 },							// OUT ib
	{ 0xE7, entry_copy_bytes2 },							// OUT ib
	{ 0xE8, entry_copy_bytes3_or_5target },				// CALL cd
	{ 0xE9, entry_copy_bytes3_or_5target },				// JMP cd
	{ 0xEA, entry_copy_bytes5_or_7dynamic },				// JMP cp
	{ 0xEB, entry_copy_bytes2_jump },						// JMP cb
	{ 0xEC, entry_copy_bytes1 },							// IN ib
	{ 0xED, entry_copy_bytes1 },							// IN id
	{ 0xEE, entry_copy_bytes1 },							// OUT
	{ 0xEF, entry_copy_bytes1 },							// OUT
	{ 0xF0, entry_copy_bytes_prefix },					// LOCK prefix 
	{ 0xF1, entry_copy_invalid },							// 
	{ 0xF2, entry_copy_bytes_prefix },					// REPNE prefix 
	{ 0xF3, entry_copy_bytes_prefix },					// REPE prefix 
	{ 0xF4, entry_copy_bytes1 },							// HLT
	{ 0xF5, entry_copy_bytes1 },							// CMC
	{ 0xF6, entry_copy_f6 },								// TEST/0, DIV/6 
	{ 0xF7, entry_copy_f7 },								// TEST/0, DIV/6 
	{ 0xF8, entry_copy_bytes1 },							// CLC
	{ 0xF9, entry_copy_bytes1 },							// STC
	{ 0xFA, entry_copy_bytes1 },							// CLI
	{ 0xFB, entry_copy_bytes1 },							// STI
	{ 0xFC, entry_copy_bytes1 },							// CLD
	{ 0xFD, entry_copy_bytes1 },							// STD
	{ 0xFE, entry_copy_bytes2_mod },						// DEC/1,INC/0
	{ 0xFF, entry_copy_ff },								// CALL/2
	{ 0, entry_end },
};


const  struct instruction_copy_entry rce_copy_table_0F[257] =
{
	{ 0x00, entry_copy_bytes2_mod },						// LLDT/2, etc. 
	{ 0x01, entry_copy_bytes2_mod },						// INVLPG/7, etc. 
	{ 0x02, entry_copy_bytes2_mod },						// LAR/r 
	{ 0x03, entry_copy_bytes2_mod },						// LSL/r 
	{ 0x04, entry_copy_invalid },							// _04 
	{ 0x05, entry_copy_invalid },							// _05 
	{ 0x06, entry_copy_bytes2 },							// CLTS 
	{ 0x07, entry_copy_invalid },							// _07 
	{ 0x08, entry_copy_bytes2 },							// INVD 
	{ 0x09, entry_copy_bytes2 },							// WBINVD 
	{ 0x0A, entry_copy_invalid },							// _0A 
	{ 0x0B, entry_copy_bytes2 },							// UD2 
	{ 0x0C, entry_copy_invalid },							// _0C 
	{ 0x0D, entry_copy_invalid },							// _0D 
	{ 0x0E, entry_copy_invalid },							// _0E 
	{ 0x0F, entry_copy_invalid },							// _0F 
	{ 0x10, entry_copy_invalid },							// _10 
	{ 0x11, entry_copy_invalid },							// _11 
	{ 0x12, entry_copy_invalid },							// _12 
	{ 0x13, entry_copy_invalid },							// _13 
	{ 0x14, entry_copy_invalid },							// _14 
	{ 0x15, entry_copy_invalid },							// _15 
	{ 0x16, entry_copy_invalid },							// _16 
	{ 0x17, entry_copy_invalid },							// _17 
	{ 0x18, entry_copy_invalid },							// _18 
	{ 0x19, entry_copy_invalid },							// _19 
	{ 0x1A, entry_copy_invalid },							// _1A 
	{ 0x1B, entry_copy_invalid },							// _1B 
	{ 0x1C, entry_copy_invalid },							// _1C 
	{ 0x1D, entry_copy_invalid },							// _1D 
	{ 0x1E, entry_copy_invalid },							// _1E 
	{ 0x1F, entry_copy_invalid },							// _1F 
	{ 0x20, entry_copy_bytes2_mod },						// MOV/r 
	{ 0x21, entry_copy_bytes2_mod },						// MOV/r 
	{ 0x22, entry_copy_bytes2_mod },						// MOV/r 
	{ 0x23, entry_copy_bytes2_mod },						// MOV/r 
	{ 0x24, entry_copy_invalid },							// _24 
	{ 0x25, entry_copy_invalid },							// _25 
	{ 0x26, entry_copy_invalid },							// _26 
	{ 0x27, entry_copy_invalid },							// _27 
	{ 0x28, entry_copy_invalid },							// _28 
	{ 0x29, entry_copy_invalid },							// _29 
	{ 0x2A, entry_copy_invalid },							// _2A 
	{ 0x2B, entry_copy_invalid },							// _2B 
	{ 0x2C, entry_copy_invalid },							// _2C 
	{ 0x2D, entry_copy_invalid },							// _2D 
	{ 0x2E, entry_copy_invalid },							// _2E 
	{ 0x2F, entry_copy_invalid },							// _2F 
	{ 0x30, entry_copy_bytes2 },							// WRMSR 
	{ 0x31, entry_copy_bytes2 },							// RDTSC 
	{ 0x32, entry_copy_bytes2 },							// RDMSR 
	{ 0x33, entry_copy_bytes2 },							// RDPMC 
	{ 0x34, entry_copy_bytes2 },							// SYSENTER 
	{ 0x35, entry_copy_bytes2 },							// SYSEXIT 
	{ 0x36, entry_copy_invalid },							// _36 
	{ 0x37, entry_copy_invalid },							// _37 
	{ 0x38, entry_copy_invalid },							// _38 
	{ 0x39, entry_copy_invalid },							// _39 
	{ 0x3A, entry_copy_invalid },							// _3A 
	{ 0x3B, entry_copy_invalid },							// _3B 
	{ 0x3C, entry_copy_invalid },							// _3C 
	{ 0x3D, entry_copy_invalid },							// _3D 
	{ 0x3E, entry_copy_invalid },							// _3E 
	{ 0x3F, entry_copy_invalid },							// _3F 
	{ 0x40, entry_copy_bytes2_mod },						// CMOVO (0F 40) 
	{ 0x41, entry_copy_bytes2_mod },						// CMOVNO (0F 41) 
	{ 0x42, entry_copy_bytes2_mod },						// CMOVB & CMOVNE (0F 42) 
	{ 0x43, entry_copy_bytes2_mod },						// CMOVAE & CMOVNB (0F 43) 
	{ 0x44, entry_copy_bytes2_mod },						// CMOVE & CMOVZ (0F 44) 
	{ 0x45, entry_copy_bytes2_mod },						// CMOVNE & CMOVNZ (0F 45) 
	{ 0x46, entry_copy_bytes2_mod },						// CMOVBE & CMOVNA (0F 46) 
	{ 0x47, entry_copy_bytes2_mod },						// CMOVA & CMOVNBE (0F 47) 
	{ 0x48, entry_copy_bytes2_mod },						// CMOVS (0F 48) 
	{ 0x49, entry_copy_bytes2_mod },						// CMOVNS (0F 49) 
	{ 0x4A, entry_copy_bytes2_mod },						// CMOVP & CMOVPE (0F 4A) 
	{ 0x4B, entry_copy_bytes2_mod },						// CMOVNP & CMOVPO (0F 4B) 
	{ 0x4C, entry_copy_bytes2_mod },						// CMOVL & CMOVNGE (0F 4C) 
	{ 0x4D, entry_copy_bytes2_mod },						// CMOVGE & CMOVNL (0F 4D) 
	{ 0x4E, entry_copy_bytes2_mod },						// CMOVLE & CMOVNG (0F 4E) 
	{ 0x4F, entry_copy_bytes2_mod },						// CMOVG & CMOVNLE (0F 4F) 
	{ 0x50, entry_copy_invalid },							// _50 
	{ 0x51, entry_copy_invalid },							// _51 
	{ 0x52, entry_copy_invalid },							// _52 
	{ 0x53, entry_copy_invalid },							// _53 
	{ 0x54, entry_copy_invalid },							// _54 
	{ 0x55, entry_copy_invalid },							// _55 
	{ 0x56, entry_copy_invalid },							// _56 
	{ 0x57, entry_copy_invalid },							// _57 
	{ 0x58, entry_copy_invalid },							// _58 
	{ 0x59, entry_copy_invalid },							// _59 
	{ 0x5A, entry_copy_invalid },							// _5A 
	{ 0x5B, entry_copy_invalid },							// _5B 
	{ 0x5C, entry_copy_invalid },							// _5C 
	{ 0x5D, entry_copy_invalid },							// _5D 
	{ 0x5E, entry_copy_invalid },							// _5E 
	{ 0x5F, entry_copy_invalid },							// _5F 
	{ 0x60, entry_copy_bytes2_mod },						// PUNPCKLBW/r 
	{ 0x61, entry_copy_invalid },							// _61 
	{ 0x62, entry_copy_bytes2_mod },						// PUNPCKLWD/r 
	{ 0x63, entry_copy_bytes2_mod },						// PACKSSWB/r 
	{ 0x64, entry_copy_bytes2_mod },						// PCMPGTB/r 
	{ 0x65, entry_copy_bytes2_mod },						// PCMPGTW/r 
	{ 0x66, entry_copy_bytes2_mod },						// PCMPGTD/r 
	{ 0x67, entry_copy_bytes2_mod },						// PACKUSWB/r 
	{ 0x68, entry_copy_bytes2_mod },						// PUNPCKHBW/r 
	{ 0x69, entry_copy_bytes2_mod },						// PUNPCKHWD/r 
	{ 0x6A, entry_copy_bytes2_mod },						// PUNPCKHDQ/r 
	{ 0x6B, entry_copy_bytes2_mod },						// PACKSSDW/r 
	{ 0x6C, entry_copy_invalid },							// _6C 
	{ 0x6D, entry_copy_invalid },							// _6D 
	{ 0x6E, entry_copy_bytes2_mod },						// MOVD/r 
	{ 0x6F, entry_copy_bytes2_mod },						// MOV/r 
	{ 0x70, entry_copy_invalid },							// _70 
	{ 0x71, entry_copy_bytes2_mod1 },						// PSLLW/6 ib,PSRAW/4 ib,PSRLW/2 ib 
	{ 0x72, entry_copy_bytes2_mod1 },						// PSLLD/6 ib,PSRAD/4 ib,PSRLD/2 ib 
	{ 0x73, entry_copy_bytes2_mod1 },						// PSLLQ/6 ib,PSRLQ/2 ib 
	{ 0x74, entry_copy_bytes2_mod },						// PCMPEQB/r 
	{ 0x75, entry_copy_bytes2_mod },						// PCMPEQW/r 
	{ 0x76, entry_copy_bytes2_mod },						// PCMPEQD/r 
	{ 0x77, entry_copy_bytes2 },							// EMMS 
	{ 0x78, entry_copy_invalid },							// _78 
	{ 0x79, entry_copy_invalid },							// _79 
	{ 0x7A, entry_copy_invalid },							// _7A 
	{ 0x7B, entry_copy_invalid },							// _7B 
	{ 0x7C, entry_copy_invalid },							// _7C 
	{ 0x7D, entry_copy_invalid },							// _7D 
	{ 0x7E, entry_copy_bytes2_mod },						// MOVD/r 
	{ 0x7F, entry_copy_bytes2_mod },						// MOV/r 
	{ 0x80, entry_copy_bytes3_or_5target },				// JO 
	{ 0x81, entry_copy_bytes3_or_5target },				// JNO 
	{ 0x82, entry_copy_bytes3_or_5target },				// JB,JC,JNAE 
	{ 0x83, entry_copy_bytes3_or_5target },				// JAE,JNB,JNC 
	{ 0x84, entry_copy_bytes3_or_5target },				// JE,JZ,JZ 
	{ 0x85, entry_copy_bytes3_or_5target },				// JNE,JNZ 
	{ 0x86, entry_copy_bytes3_or_5target },				// JBE,JNA 
	{ 0x87, entry_copy_bytes3_or_5target },				// JA,JNBE 
	{ 0x88, entry_copy_bytes3_or_5target },				// JS 
	{ 0x89, entry_copy_bytes3_or_5target },				// JNS 
	{ 0x8A, entry_copy_bytes3_or_5target },				// JP,JPE 
	{ 0x8B, entry_copy_bytes3_or_5target },				// JNP,JPO 
	{ 0x8C, entry_copy_bytes3_or_5target },				// JL,NGE 
	{ 0x8D, entry_copy_bytes3_or_5target },				// JGE,JNL 
	{ 0x8E, entry_copy_bytes3_or_5target },				// JLE,JNG 
	{ 0x8F, entry_copy_bytes3_or_5target },				// JG,JNLE 
	{ 0x90, entry_copy_bytes2_mod },						// CMOVO (0F 40) 
	{ 0x91, entry_copy_bytes2_mod },						// CMOVNO (0F 41) 
	{ 0x92, entry_copy_bytes2_mod },						// CMOVB & CMOVC & CMOVNAE (0F 42) 
	{ 0x93, entry_copy_bytes2_mod },						// CMOVAE & CMOVNB & CMOVNC (0F 43) 
	{ 0x94, entry_copy_bytes2_mod },						// CMOVE & CMOVZ (0F 44) 
	{ 0x95, entry_copy_bytes2_mod },						// CMOVNE & CMOVNZ (0F 45) 
	{ 0x96, entry_copy_bytes2_mod },						// CMOVBE & CMOVNA (0F 46) 
	{ 0x97, entry_copy_bytes2_mod },						// CMOVA & CMOVNBE (0F 47) 
	{ 0x98, entry_copy_bytes2_mod },						// CMOVS (0F 48) 
	{ 0x99, entry_copy_bytes2_mod },						// CMOVNS (0F 49) 
	{ 0x9A, entry_copy_bytes2_mod },						// CMOVP & CMOVPE (0F 4A) 
	{ 0x9B, entry_copy_bytes2_mod },						// CMOVNP & CMOVPO (0F 4B) 
	{ 0x9C, entry_copy_bytes2_mod },						// CMOVL & CMOVNGE (0F 4C) 
	{ 0x9D, entry_copy_bytes2_mod },						// CMOVGE & CMOVNL (0F 4D) 
	{ 0x9E, entry_copy_bytes2_mod },						// CMOVLE & CMOVNG (0F 4E) 
	{ 0x9F, entry_copy_bytes2_mod },						// CMOVG & CMOVNLE (0F 4F) 
	{ 0xA0, entry_copy_bytes2 },							// PUSH 
	{ 0xA1, entry_copy_bytes2 },							// POP 
	{ 0xA2, entry_copy_bytes2 },							// CPUID 
	{ 0xA3, entry_copy_bytes2_mod },						// BT  (0F A3)   
	{ 0xA4, entry_copy_bytes2_mod1 },						// SHLD  
	{ 0xA5, entry_copy_bytes2_mod },						// SHLD  
	{ 0xA6, entry_copy_invalid },							// _A6 
	{ 0xA7, entry_copy_invalid },							// _A7 
	{ 0xA8, entry_copy_bytes2 },							// PUSH 
	{ 0xA9, entry_copy_bytes2 },							// POP 
	{ 0xAA, entry_copy_bytes2 },							// RSM 
	{ 0xAB, entry_copy_bytes2_mod },						// BTS (0F AB) 
	{ 0xAC, entry_copy_bytes2_mod1 },						// SHRD  
	{ 0xAD, entry_copy_bytes2_mod },						// SHRD  
	{ 0xAE, entry_copy_bytes2_mod },						// FXRSTOR/1,FXSAVE/0 
	{ 0xAF, entry_copy_bytes2_mod },						// IMUL (0F AF) 
	{ 0xB0, entry_copy_bytes2_mod },						// CMPXCHG (0F B0) 
	{ 0xB1, entry_copy_bytes2_mod },						// CMPXCHG (0F B1) 
	{ 0xB2, entry_copy_bytes2_mod },						// LSS/r 
	{ 0xB3, entry_copy_bytes2_mod },						// BTR (0F B3) 
	{ 0xB4, entry_copy_bytes2_mod },						// LFS/r 
	{ 0xB5, entry_copy_bytes2_mod },						// LGS/r 
	{ 0xB6, entry_copy_bytes2_mod },						// MOVZX/r 
	{ 0xB7, entry_copy_bytes2_mod },						// MOVZX/r 
	{ 0xB8, entry_copy_invalid },							// _B8 
	{ 0xB9, entry_copy_invalid },							// _B9 
	{ 0xBA, entry_copy_bytes2_mod1 },						// BT & BTC & BTR & BTS (0F BA) 
	{ 0xBB, entry_copy_bytes2_mod },						// BTC (0F BB) 
	{ 0xBC, entry_copy_bytes2_mod },						// BSF (0F BC) 
	{ 0xBD, entry_copy_bytes2_mod },						// BSR (0F BD) 
	{ 0xBE, entry_copy_bytes2_mod },						// MOVSX/r 
	{ 0xBF, entry_copy_bytes2_mod },						// MOVSX/r 
	{ 0xC0, entry_copy_bytes2_mod },						// XADD/r 
	{ 0xC1, entry_copy_bytes2_mod },						// XADD/r 
	{ 0xC2, entry_copy_invalid },							// _C2 
	{ 0xC3, entry_copy_invalid },							// _C3 
	{ 0xC4, entry_copy_invalid },							// _C4 
	{ 0xC5, entry_copy_invalid },							// _C5 
	{ 0xC6, entry_copy_invalid },							// _C6 
	{ 0xC7, entry_copy_bytes2_mod },						// CMPXCHG8B (0F C7) 
	{ 0xC8, entry_copy_bytes2 },							// BSWAP 0F C8 + rd 
	{ 0xC9, entry_copy_bytes2 },							// BSWAP 0F C8 + rd 
	{ 0xCA, entry_copy_bytes2 },							// BSWAP 0F C8 + rd 
	{ 0xCB, entry_copy_bytes2 },							// BSWAP 0F C8 + rd 
	{ 0xCC, entry_copy_bytes2 },							// BSWAP 0F C8 + rd 
	{ 0xCD, entry_copy_bytes2 },							// BSWAP 0F C8 + rd 
	{ 0xCE, entry_copy_bytes2 },							// BSWAP 0F C8 + rd 
	{ 0xCF, entry_copy_bytes2 },							// BSWAP 0F C8 + rd 
	{ 0xD0, entry_copy_invalid },							// _D0 
	{ 0xD1, entry_copy_bytes2_mod },						// PSRLW/r 
	{ 0xD2, entry_copy_bytes2_mod },						// PSRLD/r 
	{ 0xD3, entry_copy_bytes2_mod },						// PSRLQ/r 
	{ 0xD4, entry_copy_invalid },							// _D4 
	{ 0xD5, entry_copy_bytes2_mod },						// PMULLW/r 
	{ 0xD6, entry_copy_invalid },							// _D6 
	{ 0xD7, entry_copy_invalid },							// _D7 
	{ 0xD8, entry_copy_bytes2_mod },						// PSUBUSB/r 
	{ 0xD9, entry_copy_bytes2_mod },						// PSUBUSW/r 
	{ 0xDA, entry_copy_invalid },							// _DA 
	{ 0xDB, entry_copy_bytes2_mod },						// PAND/r 
	{ 0xDC, entry_copy_bytes2_mod },						// PADDUSB/r 
	{ 0xDD, entry_copy_bytes2_mod },						// PADDUSW/r 
	{ 0xDE, entry_copy_invalid },							// _DE 
	{ 0xDF, entry_copy_bytes2_mod },						// PANDN/r 
	{ 0xE0, entry_copy_invalid },							// _E0 
	{ 0xE1, entry_copy_bytes2_mod },						// PSRAW/r 
	{ 0xE2, entry_copy_bytes2_mod },						// PSRAD/r 
	{ 0xE3, entry_copy_invalid },							// _E3 
	{ 0xE4, entry_copy_invalid },							// _E4 
	{ 0xE5, entry_copy_bytes2_mod },						// PMULHW/r 
	{ 0xE6, entry_copy_invalid },							// _E6 
	{ 0xE7, entry_copy_invalid },							// _E7 
	{ 0xE8, entry_copy_bytes2_mod },						// PSUBB/r 
	{ 0xE9, entry_copy_bytes2_mod },						// PSUBW/r 
	{ 0xEA, entry_copy_invalid },							// _EA 
	{ 0xEB, entry_copy_bytes2_mod },						// POR/r 
	{ 0xEC, entry_copy_bytes2_mod },						// PADDSB/r 
	{ 0xED, entry_copy_bytes2_mod },						// PADDSW/r 
	{ 0xEE, entry_copy_invalid },							// _EE 
	{ 0xEF, entry_copy_bytes2_mod },						// PXOR/r 
	{ 0xF0, entry_copy_invalid },							// _F0 
	{ 0xF1, entry_copy_bytes2_mod },						// PSLLW/r 
	{ 0xF2, entry_copy_bytes2_mod },						// PSLLD/r 
	{ 0xF3, entry_copy_bytes2_mod },						// PSLLQ/r 
	{ 0xF4, entry_copy_invalid },							// _F4 
	{ 0xF5, entry_copy_bytes2_mod },						// PMADDWD/r 
	{ 0xF6, entry_copy_invalid },							// _F6 
	{ 0xF7, entry_copy_invalid },							// _F7 
	{ 0xF8, entry_copy_bytes2_mod },						// PSUBB/r 
	{ 0xF9, entry_copy_bytes2_mod },						// PSUBW/r 
	{ 0xFA, entry_copy_bytes2_mod },						// PSUBD/r 
	{ 0xFB, entry_copy_invalid },							// _FB 
	{ 0xFC, entry_copy_bytes2_mod },						// PADDB/r 
	{ 0xFD, entry_copy_bytes2_mod },						// PADDW/r 
	{ 0xFE, entry_copy_bytes2_mod },						// PADDD/r 
	{ 0xFF, entry_copy_invalid },							// _FF 
	{ 0, entry_end },
};
//////////////////////////////////////////////////////////////////////////

pbyte  __stdcall adjust_target(pbyte dst , pbyte src , long op , long target_offset , icp* cp)
{
	long target_size = op - target_offset;
	pbyte target = NULL;
	pvoid target_addr = &dst[target_offset];
	long old_offset = 0 , new_offset = 0;

	switch (target_size) 
	{
	case 1:
		old_offset = (long)*(pchar)target_addr;
		*cp->extra_ptr = 3;
		break;
	case 2:
		old_offset = (long)*(pshort)target_addr;
		*cp->extra_ptr = 2;
		break;
	case 4:
		old_offset = (long)*(plong)target_addr;
		*cp->extra_ptr = 0;
		break;
#ifdef DBG
	default:
		DBG_OUT("detour : target_size is invalid.\r\n");
		break;
#endif 
	}

	target = src + op + old_offset;
	new_offset = old_offset - (dst - src);

	switch (target_size)
	{
	case 1:
		*(pchar)target_addr = (char)new_offset;
		break;
	case 2:
		*(pshort)target_addr = (short)new_offset;
		break;
	case 4:
		*(plong)target_addr = (long)new_offset;
		break;
	}

#ifdef DBG
	if(dst + op + new_offset != target)
		DBG_OUT("detour : dst + op + new_offset !== target \r\n");
#endif

	return target;
}

pbyte  __stdcall copy_invalid(ref_ice entry , pbyte dst , pbyte src , icp* cp)
{
#ifdef DBG
	DBG_OUT("detour : invalid instruction.\r\n");
#endif
	return src + 1;
}

pbyte  __stdcall copy_bytes(ref_ice entry , pbyte dst , pbyte src , icp* cp)
{
	long bytes_fixed , bytes;

	bytes_fixed = (entry->flags & mod_offset_address)
		? (cp->is_16bit_address ? entry->fix_size16 : entry->fix_size)
		: (cp->is_16bit_operand ? entry->fix_size16 : entry->fix_size);

	bytes = bytes_fixed;

	if(entry->mod_offset > 0)
	{
		byte mod_rm , flags;
		mod_rm = src[entry->mod_offset];
		flags = rb_mod_rm[mod_rm];

		if(flags & mod_offset_sib)
		{
			byte sib = src[entry->mod_offset + 1];

			if((sib & 0x07) == 0x05)
			{
				switch(mod_rm & 0xc0)
				{
				case 0x40:
					bytes += 1;
					break;
				case 0x00:
				case 0x80:
					bytes += 4;
				}
			}
		}
		bytes += flags & mod_offset_notsib;
	}
	RtlCopyMemory(dst , src , bytes);

	if(entry->rel_offset)
		*cp->target_pptr = adjust_target(dst , src , bytes_fixed , entry->rel_offset , cp);

	if(entry->flags & mod_offset_noenlarge)
		*cp->extra_ptr = -*cp->extra_ptr;

	if(entry->flags & mod_offset_dynamic)
		*cp->target_pptr = DETOUR_INSTRUCTION_TARGET_DYNAMIC;

	return src + bytes;
}

pbyte  __stdcall copy_bytes_prefix(ref_ice entry , pbyte dst , pbyte src , icp *cp)
{
	copy_bytes(entry , dst , src , cp);
	entry = &rce_copy_table[src[1]];
	return entry->copy_fun(entry , dst + 1 , src + 1 , cp);
}

////////////////////////////////////////////////////// Individual Bytes Codes.
pbyte  __stdcall copy_0f(ref_ice entry , pbyte dst , pbyte src , icp *cp)
{
	copy_bytes(entry , dst , src , cp);
	entry = &rce_copy_table[src[1]];
	return entry->copy_fun(entry , dst + 1 , src + 1 , cp);
}

pbyte  __stdcall copy_66(ref_ice entry , pbyte dst , pbyte src , icp *cp)
{
	cp->is_16bit_operand = TRUE;
	return copy_bytes_prefix(entry , dst , src , cp);
}

pbyte  __stdcall copy_67(ref_ice entry , pbyte dst , pbyte src , icp *cp)
{
	cp->is_16bit_address = TRUE;
	return copy_bytes_prefix(entry , dst , src , cp);
}

pbyte  __stdcall copy_F6(ref_ice entry , pbyte dst , pbyte src , icp *cp)
{
	(void)entry;

	if((src[1] & 0x38) == 0x00)
	{
		const struct instruction_copy_entry ce = {0xf6 , entry_copy_bytes2_mod1};
		return ce.copy_fun(&ce , dst , src , cp);
	}
	else
	{
		const struct instruction_copy_entry ce = {0xf6 , entry_copy_bytes2_mod};
		return ce.copy_fun(&ce , dst , src , cp);
	}
}

pbyte  __stdcall copy_F7(ref_ice entry , pbyte dst , pbyte src , icp * cp)
{
	(void)entry;
	if((src[1] & 0x38) == 0x00)
	{
		const struct instruction_copy_entry ce = {0xf7 , entry_copy_bytes2_mod_operand};
		return ce.copy_fun(&ce , dst , src , cp);
	}
	else
	{
		const struct instruction_copy_entry ce = {0xf7 , entry_copy_bytes2_mod};
		return ce.copy_fun(&ce , dst , src , cp);
	}
}

pbyte  __stdcall copy_FF(ref_ice entry , pbyte dst , pbyte src , icp * cp)
{
	const struct instruction_copy_entry ce = {0xff , entry_copy_bytes2_mod};

	(void)entry;

	if(src[1] == 0x15
		|| src[1] == 0x25)
	{
		pbyte* target_pptr = *(pbyte**)&src[2];
		*cp->target_pptr = *target_pptr;
	}
	else if( (src[1] & 0x38) == 0x10
		|| (src[1] & 0x38) == 0x18
		|| (src[1] & 0x38) == 0x20
		|| (src[1] & 0x38) == 0x28)
		*cp->target_pptr = DETOUR_INSTRUCTION_TARGET_DYNAMIC;

	return ce.copy_fun(&ce , dst , src , cp);
}

//////////////////////////////////////////////////////////////////////////

void  __stdcall icp_init(icp * cp
						 , pbyte* target_pptr /* = NULL  */
						 , plong extra_ptr /* = NULL  */
						 , byte is_16bit_operand /* = false  */
						 , byte is_16bit_address /* = false */)
{
	cp->is_16bit_address = is_16bit_address;
	cp->is_16bit_operand = is_16bit_operand;

	cp->target_pptr = target_pptr ? target_pptr : &cp->scratch_target;
	cp->extra_ptr = extra_ptr ? extra_ptr : &cp->scratch_extra;

	*cp->target_pptr = DETOUR_INSTRUCTION_TARGET_NONE;
	*cp->extra_ptr = 0;
}

pbyte	 __stdcall icp_copy_instruction(icp *cp , pbyte dst , pbyte src)
{
	if(NULL == dst)
		dst = cp->scratch_dst;
	if(NULL == src)
		return NULL;
	else
	{
		ref_ice entry = &rce_copy_table[src[0]];
		return entry->copy_fun(entry , dst , src , cp);
	}
}


NTSTATUS	__stdcall detour_sanity_check()
{
	ulong n = 0;
	for (; n < 256; n++) 
	{
		ref_ice entry = &rce_copy_table[n];
		if (n != entry->op_code) 
		{
			DBG_OUT("detour : op_code != %08x !\r\n" , entry->op_code);
			return STATUS_UNSUCCESSFUL;
		}
	}

	if (rce_copy_table[256].copy_fun != NULL)
	{
		DBG_OUT("detour : missing end marker.\r\n");
		return STATUS_UNSUCCESSFUL;
	}

	for (n = 0; n < 256; n++) 
	{
		ref_ice entry = &rce_copy_table_0F[n];

		if (n != entry->op_code) 
		{
			DBG_OUT("detour : op_code != %08x !\r\n" , entry->op_code);
			return STATUS_UNSUCCESSFUL;
		}
	}

	if (rce_copy_table_0F[256].copy_fun != NULL)
	{
		DBG_OUT("detour : missing end marker.\r\n");
		return STATUS_UNSUCCESSFUL;
	}

	return STATUS_SUCCESS;
}



pbyte __stdcall detour_copy_instruction(pbyte dst , pbyte src , pbyte * target_pptr , long* extra)
{
	icp cp;
	icp_init(&cp , target_pptr , extra , 0 , 0);
	return icp_copy_instruction(&cp , dst , src);
}


