#include <windows.h>
extern "C" __declspec(dllexport) int candidate_fixture(){return 42;}
BOOL WINAPI DllMain(HINSTANCE,DWORD,LPVOID){return TRUE;}
