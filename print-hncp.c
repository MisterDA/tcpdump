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

/* TLVs */
#define HNCP_VERSION 32

void
hncp_print(netdissect_options *ndo,
            const u_char *cp, u_int length)
{
    ND_PRINT((ndo, "hncp"));
    
    u_int i = 0;
    
    //ND_PRINT((ndo, " (%d)", length));
    
    while(i<length) {
        const u_char *tlv = cp + i;
        
        ND_TCHECK2(*tlv, 4);
        
        const u_short type = EXTRACT_16BITS(tlv);
        const u_short len = EXTRACT_16BITS(tlv+2);
        ND_TCHECK2(*tlv, 4+len);
        
        switch (type) {
            
            case HNCP_VERSION: {
                // do stuff
            }
                break;
            
        }
        
        
        
        
        
        
        
        
        /*
        ND_PRINT((ndo, " %d (%d)", type, len));
        for (int a=0; a<len; a++) {
            ND_PRINT((ndo, " %02hhX", *(tlv+4+a) ));
        }
        //*/
        
        i += 4+len;
    }
    return;
    
    trunc:
       ND_PRINT((ndo, " %s", tstr));
       return;
}
