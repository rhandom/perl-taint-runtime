#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"
#include "ppport.h"

MODULE = Taint::Runtime		PACKAGE = Taint::Runtime

int
_start_taint()
  CODE:
    PL_tainting = 1;
    RETVAL = 1;
  OUTPUT:
    RETVAL

int
_stop_taint()
  CODE:
    PL_tainting = 0;
    RETVAL = 1;
  OUTPUT:
    RETVAL

SV*
_tainted()
  CODE:
    PL_tainted = 1;
    RETVAL = newSVpvn("", 0);
  OUTPUT:
    RETVAL
