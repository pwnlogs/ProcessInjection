;              TEST PAYLOAD
; Function to call MessageBoxA() function
; Prototype: function(address of MessageBoxA)
;
push   ebp
mov    ebp,esp
sub    esp,0x8
mov    BYTE PTR [ebp-0x4],0x48
mov    BYTE PTR [ebp-0x3],0x0
mov    BYTE PTR [ebp-0x8],0x46
mov    BYTE PTR [ebp-0x7],0x0
push   eax
push   ebx
push   ecx
push   edx
push   edi
push   esi
push   0x0
lea    eax,[ebp-0x4]
push   eax
lea    eax,[ebp-0x8]
push   eax
push   0x0
call   DWORD PTR [ebp+0x8]
pop    esi
pop    edi
pop    edx
pop    ecx
pop    ebx
pop    eax
xor    eax, eax
mov    esp,ebp
pop    ebp
ret