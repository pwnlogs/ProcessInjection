/*  -----------------------------------------------------------------------
                  APC Injection payload written in pure C                
    -----------------------------------------------------------------------
    Steps:
        1. compile the fie using 
                cl callMsg.cpp /c /Gz /GS- /Od
            ( 
              /c  : only generate .obj file, don't link
              /Gz : use __stdcall convention
              /GS-: don't add any security checks
              /Od : don't do any optimizations 
            )
        2. use OtoS.py to convert callMsg.obj to string using
                python OtoS.py callMsg.obj 369 184
        3. Copy contents of callMsg.obj.txt to apcInjectionNoDll.cpp as executor
   
    During injection,
        Address of MessageBox should be passed as the argument to this function
  */

#include <windows.h>

typedef void func(HWND, LPCTSTR, LPCTSTR, UINT);

void __stdcall Papcfunc(ULONG_PTR parameter){
    char title[] = {'T','i','t','l','e', 0};
    char msg[] = {'M','e','s','s','a','g','e', 0};
    func* msgBox = (func*) parameter;
    msgBox(NULL, msg, title, 0x00000000L);
}
