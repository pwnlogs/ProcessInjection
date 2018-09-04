#include <Windows.h>
#include <iostream>
#include <TlHelp32.h>

using namespace std;

BOOL Dll_Injection(const char* dll_name, const char* processname){
	char lpdllpath[MAX_PATH];
	GetFullPathName(dll_name, MAX_PATH, lpdllpath, nullptr);
	cout<<"[i] full path: "<<lpdllpath<<endl;

	/* Finding specified process */
	DWORD processId{};
	cout<<"[+] creating process snapshot\n";
	auto snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0); 
	if (snapshot == INVALID_HANDLE_VALUE){
		cout<<"[!] failed to create process snapshot\n";
		return FALSE;
	}
	cout<<"[+] created process snapshot\n\n";
	PROCESSENTRY32 pe{};
	pe.dwSize = sizeof PROCESSENTRY32;
	BOOL processFound = FALSE;
	if(Process32First(snapshot, &pe)==FALSE){
		cout<<"[!] unable to retrive first process in the snapshot"<<endl;
		CloseHandle(snapshot);
		return FALSE;
	}
	if(stricmp(pe.szExeFile, processname)==0){
		processId = pe.th32ProcessID;
		processFound = TRUE;
		cout<<"[i] found the process '"<<processname<<"'\n";
		cout<<"[i] process id: "<< processId<<endl;
		cout<<"[+] closing handle to process snapshot\n";
		CloseHandle(snapshot);
	}
	while(!processFound && Process32Next(snapshot, &pe)==TRUE){   // as long as there are processes in the list
		if (_stricmp(pe.szExeFile, processname) == 0){
			processFound = TRUE;
			processId = pe.th32ProcessID;
			cout<<"[i] found the process '"<<processname<<"'\n";
			cout<<"[i] process id: "<< processId<<endl;
			cout<<"[+] closing handle to process snapshot\n";
			CloseHandle(snapshot);
		}
	}
	if(!processFound){
		cout<<"[!] process not found"<<endl;
		return FALSE;
	}

	/* Write full path of dll to victim process's memory */
	auto size = strlen(lpdllpath)*sizeof(TCHAR); // len of dll's path
	auto victimProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, processId);
	if(victimProcess==NULL){
		cout<<"failed to get handle for process: "<<processId<<endl;
		return FALSE;
	}
	cout<<"[+] obtained handle to victim(host) process"<<endl;
	LPVOID baseAddressInVictimProcess = VirtualAllocEx(
		victimProcess,				// handle for victim process
		NULL,						// let function decide where to allocate
		size,						// size to allocate (size of dll's path)
		MEM_COMMIT | MEM_RESERVE,	// commit as well as reserve the addresses
		PAGE_READWRITE);			// enable only read-write (no execution needed)
	if(baseAddressInVictimProcess==NULL) {
		cout<<"[!] memory allocation failed!"<<endl;
		return FALSE;
	}
	cout<<"[+] allocated memory in victim(host) process"<<endl;
	cout<<"[i] starting addess: 0x"<<baseAddressInVictimProcess<<endl;
	if(WriteProcessMemory(
		victimProcess,
		baseAddressInVictimProcess,
		lpdllpath,
		size,
		NULL)==0){
		cout<<"[!] write to victim process memory failed"<<endl;
		return FALSE;
	}
	cout<<"[+] write to victim process memory successful"<<endl;

	/* Creating remote thread(in victim process)
	   with a call to LoadLibrary() to load dll to victim process */
	auto kernel32 = GetModuleHandle("kernel32.dll");
	if(kernel32==NULL){
		cout<<"[!] undable to find kernel32!"<<endl;
		return FALSE;
	}
	cout<<"[+] obtained handle to kernel32"<<endl;
	
	auto loadLibAddr = GetProcAddress(kernel32, "LoadLibraryA");
	if(loadLibAddr==NULL){
		cout<<"[!] failed to find LoadLibrary"<<endl;
		return FALSE;
	}
	cout<<"[i] LoadLibraryA address: "<<loadLibAddr<<endl;

	DWORD remoteThreadId = -1;
	HANDLE remoteThreadHandle = CreateRemoteThread(
		victimProcess,
		NULL,
		0,
		reinterpret_cast<LPTHREAD_START_ROUTINE>(loadLibAddr),
		baseAddressInVictimProcess,
		// CREATE_SUSPENDED,
		0,
		&remoteThreadId);
	if(remoteThreadHandle==NULL){
		cout<<"[!] failed to create remote process"<<endl;
		return FALSE;
	}
	cout<<"[+] remote thread created"<<endl;
	cout<<"[i] id: 0x"<<std::hex<<remoteThreadId<<std::dec<<"("<<remoteThreadId<<")"<<std::dec<<endl;
	// Sleep(15000);
	// ResumeThread(remoteThreadHandle);
	// cout<<"[+] remote thread started"<<endl;
	DWORD threadStatus = WaitForSingleObject(remoteThreadHandle, INFINITE);
	if(threadStatus!=WAIT_OBJECT_0){
		cout<<"[!] thread termination status unkown"<<endl;
		return FALSE;
	}
	cout<<"[+] remote thread execution completed"<<endl;
	DWORD returnValue=-1;
	if(GetExitCodeThread(remoteThreadHandle, &returnValue)==0){
		cout<<"[!] failed to retrieve return status"<<endl;
		return FALSE;
	}
	cout<<"[+] return value: "<<returnValue<<endl;	

	/* Cleaning up */
	cout<<"[+] cleaning up..."<<endl;
	CloseHandle(victimProcess);
	CloseHandle(remoteThreadHandle);
	VirtualFreeEx(victimProcess, baseAddressInVictimProcess, size, MEM_RELEASE);
	cout<<"[+] injection SUCCESSFUL";
	return TRUE;
}


int main(int argc, char* argv[]){
	Dll_Injection(argv[1], argv[2]);
}