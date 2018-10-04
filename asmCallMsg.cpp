
unsigned long popMsg(unsigned long *executer){

	char m1[] = { 'H', 0 };
	char m2[] = { 'F', 0 };
	unsigned long executerStr = *executer;

	_asm {
		push    eax
		push    0               // uType
		lea 	eax,	m1
		push    eax			    // "From DLL"
		lea 	eax, 	m2
		push    eax		 	    // "Hello"
		push    0               // hWnd
		call    executerStr
		add 	esp, 	0x10	// 4x4
		pop 	eax
	}

    return 0;
}