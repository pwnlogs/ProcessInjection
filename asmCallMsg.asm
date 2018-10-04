push   ebp
mov    ebp,esp
sub    esp,0xc
mov    BYTE PTR [ebp-0x4],0x48
mov    BYTE PTR [ebp-0x3],0x0
mov    BYTE PTR [ebp-0x8],0x46
mov    BYTE PTR [ebp-0x7],0x0
mov    eax,DWORD PTR [ebp+0x8]
mov    ecx,DWORD PTR [eax]
mov    DWORD PTR [ebp-0xc],ecx
push   eax
push   0x0
lea    eax,[ebp-0x4]
push   eax
lea    eax,[ebp-0x8]
push   eax
push   0x0
call   DWORD PTR [ebp+0x8]
add    esp,0x10
pop    eax
xor    eax,eax
mov    esp,ebp
pop    ebp
ret                         