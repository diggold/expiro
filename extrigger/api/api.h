
///////////////////////////////////////////////////////
// Init IP by string

//sample: 
// DWORD  *adr[] = {&_OpenMutex, &_CloseHandle,&_ExitThread,&_CreateFile};
// InitAPIbyStr(adr,KERNEL32,"/*@S|*/00OpenMutexA|01CloseHandle|02ExitThread/*@E*/|");

#ifdef _MSC_VER
	#pragma optimize("", off)
#else
	#pragma optimize(off)
#endif


///*@S|*/00GetModuleHandleA|01LoadLibraryA/*@E*/|
void InitAPIbyStr(DWORD *adr[], HANDLE h, char *data)
{ 
	DWORD q = 0;
	DWORD f = 0;

	if (data[0]=='/') 
	{ 
		q=7;
		f=7;
	} // skip construction

loop:;
	if (data[q]==0)
		return;
	if (data[q]=='/')
	{ 
			data[q]=0; 
			q+=6; 
	} // skip construction

	// end of func name, '|'==124
	if (data[q]==124)
	{
		DWORD n = 0;
		data[q] = 0; 

		n += (data[f]-48)*10;  // '0'==48, we split calculation in 2 lines
		n += (data[f+1]-48); // to prevent lcc "long calc result=0" bug	                                      
		// bonus: improved mutation  

		//  printf("%u:'%s' _GetProcAddress:%X\n",n,&data[f+2],_GetProcAddress);
		*(adr[n]) = (DWORD)_GetProcAddress((HMODULE)h, &data[f + 2]);

		f = q + 1;
	}
	q++;
	goto loop;
}

#ifdef _MSC_VER
	#pragma optimize("", on)
#else
	#pragma optimize(on)
#endif