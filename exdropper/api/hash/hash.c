#include <stdio.h>
#include <windows.h>

int main()
{
	char fncname[]="VirtualProtect";

	DWORD lf=strlen(fncname);
	DWORD summ=0;
	DWORD humm=0;

	for (DWORD w=0;w<lf;w++) 
	{
		summ+=fncname[w]; humm+=fncname[w/2]; 
	}

	if (lf > 41) 
		return;
	
	DWORD hash = lf*100000000 + summ*10000 + humm/;
	printf("hash:%u func|lf:%u *100000000|summ:%u *10000|humm:%u|%s|",hash,lf,summ,humm,fncname);
}
