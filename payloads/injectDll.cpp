/*          TEST PAYLOAD (DLL)                      */
/*  Pop up a message box window on init of the dll  */

#include <Windows.h>
#include <tchar.h>

#pragma comment(lib,"user32.lib")

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     ){

    switch (ul_reason_for_call){
        case DLL_PROCESS_ATTACH:
            MessageBox(NULL, "Hello", "From DLL", MB_OK);
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        case DLL_PROCESS_DETACH:
            break;
    }

    return TRUE;
}