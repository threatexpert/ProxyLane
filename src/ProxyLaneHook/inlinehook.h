#ifndef INLINEHOOK_2E489178_H
#define INLINEHOOK_2E489178_H

//
//2012.04.19   by cherryEx. 83617686@qq.com
//

#ifdef   __cplusplus
extern "C"{
#endif

int hook_set(unsigned char *target, unsigned char *trampoline, void *new_handler);
int hook_remove(unsigned char *trampoline, void *new_handler);
int hook_set_hp(unsigned char *target, unsigned char *trampoline, void *new_handler, void *jmpboard);

#define JMPBOARD_SIZE   16

#define TRAMPOLINE_SIZE 134

#define no_Return ;
#define has_Return return 0;

#if defined (_MSC_VER) && (_MSC_VER <= 1200)
#define __debugbreak() { __asm int 3};
#endif

/*
定义一个TRAMPOLINE
----
一堆的__debugbreak();是用来扩充函数代码长度，这些代码空间会用来备份hook前的指令等等

其中volatile int i = 0; memset(0, 0, 0); 是故意用来干扰编译器某些优化行为

例如，1）不加volatile的时候，定义了xxxA和xxxW两个函数的trampoline，
      结果编译后，发现两个trampoline的函数地址居然是同一个（因为编译器觉得两个函数代码一样的就优化为一份了）
	  函数体内加个volatile发现可以避免这种优化

	  2）函数体内加个其他函数的调用，这里选用memset来干扰，避免调用时传参数的优化
	  那么像这样连续两次调用
	  trampoline_xxxA(arg1);
	  trampoline_xxxA(arg1); 的时候，
	  汇编应该是：
	  lea rcx, arg1  x64设置第一个参数
	  call trampoline_xxxA
	  lea rcx, arg1  再次调用是需要要再次设置的
	  call trampoline_xxxA
	  //如果不加memset来干扰，编译trampoline的代码时编译器认为该函数没任何“有意义”代码完全不会修改任何寄存器，会被优化为
	  lea rcx, arg1
	  call trampoline_xxxA
	  call trampoline_xxxA
	  上面第二次调用的时候编译器觉得不必要再次设置rcx了
-----------------
*/

#define DEFINE_TRAMPOLINE(name, ret)\
	name {\
	volatile int i = __LINE__; \
	memset(__FILE__, 0, 0); \
	__debugbreak();__debugbreak();__debugbreak();__debugbreak();\
	__debugbreak();__debugbreak();__debugbreak();__debugbreak();\
	__debugbreak();__debugbreak();__debugbreak();__debugbreak();\
	__debugbreak();__debugbreak();__debugbreak();__debugbreak();\
	__debugbreak();__debugbreak();__debugbreak();__debugbreak();\
	__debugbreak();__debugbreak();__debugbreak();__debugbreak();\
	__debugbreak();__debugbreak();__debugbreak();__debugbreak();\
	__debugbreak();__debugbreak();__debugbreak();__debugbreak();\
	__debugbreak();__debugbreak();__debugbreak();__debugbreak();\
	__debugbreak();__debugbreak();__debugbreak();__debugbreak();\
	__debugbreak();__debugbreak();__debugbreak();__debugbreak();\
	__debugbreak();__debugbreak();__debugbreak();__debugbreak();\
	__debugbreak();__debugbreak();__debugbreak();__debugbreak();\
	__debugbreak();__debugbreak();__debugbreak();__debugbreak();\
	__debugbreak();__debugbreak();__debugbreak();__debugbreak();\
	__debugbreak();__debugbreak();__debugbreak();__debugbreak();\
	__debugbreak();__debugbreak();__debugbreak();__debugbreak();\
	__debugbreak();__debugbreak();__debugbreak();__debugbreak();\
	__debugbreak();__debugbreak();__debugbreak();__debugbreak();\
	__debugbreak();__debugbreak();__debugbreak();__debugbreak();\
	__debugbreak();__debugbreak();__debugbreak();__debugbreak();\
	__debugbreak();__debugbreak();__debugbreak();__debugbreak();\
	__debugbreak();__debugbreak();__debugbreak();__debugbreak();\
	__debugbreak();__debugbreak();__debugbreak();__debugbreak();\
	__debugbreak();__debugbreak();__debugbreak();__debugbreak();\
	__debugbreak();__debugbreak();__debugbreak();__debugbreak();\
	__debugbreak();__debugbreak();__debugbreak();__debugbreak();\
	__debugbreak();__debugbreak();__debugbreak();__debugbreak();\
	__debugbreak();__debugbreak();__debugbreak();__debugbreak();\
	__debugbreak();__debugbreak();__debugbreak();__debugbreak();\
	__debugbreak();__debugbreak();__debugbreak();__debugbreak();\
	__debugbreak();__debugbreak();__debugbreak();__debugbreak();\
	__debugbreak();__debugbreak();__debugbreak();__debugbreak();\
	__debugbreak();__debugbreak();__debugbreak();__debugbreak();\
	__debugbreak();__debugbreak();__debugbreak();__debugbreak();\
	##ret;\
}



#define DETOUR_METHOD(rettype, calltype, method) rettype calltype method
#define MyDetourHook(rettype, calltype, method, args) DETOUR_METHOD(rettype, calltype, hook_##method)##args
#define MyDetourTrampoline(rettype, calltype, method, args) DETOUR_METHOD(rettype, calltype, Trampoline_##method)##args

#define MyDetourProc(returnVal,rettype, calltype, method, args)\
	DEFINE_TRAMPOLINE(MyDetourTrampoline(rettype, calltype, method, args), returnVal);\
	MyDetourHook(rettype, calltype, method, args)

#define CallTrampoline(method) Trampoline_##method

#define ENABLE_HOOK(fn) hook_set((unsigned char*)fn, (unsigned char*)Trampoline_##fn, hook_##fn)
#define DISABLE_HOOK(fn) hook_remove((unsigned char*)Trampoline_##fn, hook_##fn)
#define ENABLE_HOOK2(fn, addr) hook_set((unsigned char*)addr, (unsigned char*)Trampoline_##fn, (unsigned char*)hook_##fn)

#ifdef   __cplusplus
}
#endif


#endif //INLINEHOOK_2E489178_H