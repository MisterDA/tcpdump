#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <netdissect-stdinc.h>

#include <stdio.h>
#include <string.h>

#include "netdissect.h"
#include "addrtoname.h"
#include "extract.h"

static const char tstr[] = "[|hncp]";

void
hncp_print(netdissect_options *ndo,
            const u_char *cp, u_int length)
{
    ND_PRINT((ndo, "hncp"));

    ND_TCHECK2(*cp, 4);

    u_short type = EXTRACT_16BITS(cp);
    u_short len = EXTRACT_16BITS(cp + 2);

    ND_PRINT((ndo, " (%d)", type, len));

    return;

    trunc:
       ND_PRINT((ndo, " %s", tstr));
       return;
}
