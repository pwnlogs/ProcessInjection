#include <Windows.h>
#include <tchar.h>

#pragma comment(lib,"user32.lib")

BOOL APIENTRY DllMain(
HANDLE hModule,// Handle to DLL module
DWORD ul_reason_for_call,// Reason for calling function
LPVOID lpReserved ) // Reserved
{
	switch ( ul_reason_for_call )
	{
		case DLL_PROCESS_ATTACH:
			// A process is loading the DLL.
		    MessageBox(NULL, "Called due to dll load or process load", "injectDll", MB_OK);
			break;
		case DLL_THREAD_ATTACH:
			// A process is creating a new thread.
		    // MessageBox(NULL, "Called due to new thread creation", "injectDll", MB_OK);
			break;
		case DLL_THREAD_DETACH:
			// A thread exits normally.
		    // MessageBox(NULL, "Call due to thread termination", "injectDll", MB_OK);
			break;
		case DLL_PROCESS_DETACH:
			// A process unloads the DLL.
		    // MessageBox(NULL, "Called due to dll unload of process exit", "injectDll", MB_OK);
			break;
		default:
			;
			// MessageBox(NULL, "Called for unknown reason", "injectDll", MB_OK);
	}
	return TRUE;
}