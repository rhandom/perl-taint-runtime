#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "ppport.h"


MODULE = Taint::Runtime		PACKAGE = Taint::Runtime

void
_start_taint()
  CODE:
    PL_tainting = 1;

void
_stop_taint()
  CODE:
    PL_tainting = 0;

SV*
_tainted()
  CODE:
    PL_tainted = 1;
    RETVAL = newSVpvn("", 0);
  OUTPUT:
    RETVAL
