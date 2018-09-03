#include <Windows.h>
#include <tchar.h>

#pragma comment(lib,"user32.lib")

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    MessageBox(NULL, "Hello", "From DLL", MB_OK);
    return TRUE;
}