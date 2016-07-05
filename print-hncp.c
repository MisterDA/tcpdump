#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <netdissect-stdinc.h>

#include "netdissect.h"
#include "extract.h"

static const char tstr[] = "[|hncp]";

/* TLVs */
#define DNCP_REQUEST_NETWORK_STATE 1
#define DNCP_REQUEST_NODE_STATE 2
#define DNCP_NODE_ENDPOINT 3
#define DNCP_NETWORK_STATE 4
#define DNCP_NODE_STATE 5
#define DNCP_PEER 8
#define DNCP_KEEP_ALIVE_INTERVAL 9
#define DNCP_TRUST_VERDICT 10

/*
static const struct tok dncp_type_values[] = {
    { DNCP_REQUEST_NETWORK_STATE,	"Request network state" },
    { DNCP_REQUEST_NODE_STATE,		"Request node state" },
    { DNCP_NODE_ENDPOINT,		"Node endpoint" },
    { DNCP_NETWORK_STATE,		"Network state" },
    { DNCP_NODE_STATE,		"Network node state" },
    { DNCP_PEER,		"Peer" },
    { DNCP_KEEP_ALIVE_INTERVAL,		"Keep-alive interval" },
    { DNCP_TRUST_VERDICT,		"Trust-Verdict" },
    { 0, NULL}
};
*/

#define HNCP_VERSION 32
#define HNCP_EXTERNAL_CONNECTION 33
#define HNCP_DELEGATED_PREFIX 34
#define HNCP_PREFIX_POLICY 43
#define HNCP_DHCPV6_DATA 37
#define HNCP_DHCPV4_DATA 38
#define HNCP_ASSIGNED_PREFIX 35
#define HNCP_NODE_ADDRESS 36
#define HNCP_DNS_DELEGATED_ZONE 39
#define HNCP_DOMAIN_NAME 40
#define HNCP_NODE_NAME 41
#define HNCP_MANAGED_PSK 42

/*
static const struct tok hncp_type_values[] = {
    { HNCP_VERSION,		"HNCP-Version" },
    { HNCP_EXTERNAL_CONNECTION,		"External-Connection" },
    { HNCP_DELEGATED_PREFIX,		"Delegated-Prefix" },
    { HNCP_PREFIX_POLICY,		"Prefix-Policy" },
    { HNCP_DHCPV6_DATA,		"DHCPv6-Data" },
    { HNCP_DHCPV4_DATA,		"DHCPv4-Data" },
    { HNCP_ASSIGNED_PREFIX,	"Assigned-Prefix" },
    { HNCP_NODE_ADDRESS,		"Node-Address" },
    { HNCP_DNS_DELEGATED_ZONE,		"DNS-Delegated-Zone" },
    { HNCP_DOMAIN_NAME,		"Domain-Name" },
    { HNCP_NODE_NAME,		"Node-Name" },
    { HNCP_MANAGED_PSK,		"Managed-PSK" },
    { 0, NULL}
};
*/

static const char *
format_32(const unsigned char *data)
{
    static char buf[4][16];
    static int i = 0;
    i = (i + 1) % 4;
    snprintf(buf[i], 16, "%02x:%02x:%02x:%02x",
             data[0], data[1], data[2], data[3]);
    return buf[i];
}

const char *
format_64(const unsigned char *data)
{
    static char buf[4][28];
    static int i = 0;
    i = (i + 1) % 4;
    snprintf(buf[i], 28, "%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x",
             data[0], data[1], data[2], data[3],
             data[4], data[5], data[6], data[7]);
    return buf[i];
}

void
hncp_print(netdissect_options *ndo,
           const u_char *cp, u_int length)
{
    ND_PRINT((ndo, "hncp"));

    u_int i = 0;
    while (i < length) {
        const u_char *tlv = cp + i;
        ND_TCHECK2(*tlv, 4);
        const uint16_t type = EXTRACT_16BITS(tlv);
        const uint16_t len = EXTRACT_16BITS(tlv + 2);
        const u_char *value = tlv + 4;
        ND_TCHECK2(*value, len);

        /*
        if (ndo->ndo_vflag < 1) {
            ND_PRINT((ndo, ", %s", tok2str(dncp_type_values, "unknown", type)));
            i += len + 4;
            continue;
        }
        */

        switch (type) {
        case DNCP_REQUEST_NETWORK_STATE: {
            if (!ndo->ndo_vflag)
                ND_PRINT((ndo, ", Request network state"));
            else {
                ND_PRINT((ndo, "\n\tRequest network state"));
            }
        }
            break;

        case DNCP_REQUEST_NODE_STATE: {
            if (!ndo->ndo_vflag)
                ND_PRINT((ndo, ", Request node state"));
            else {
                ND_PRINT((ndo, "\n\tRequest node state"));
                if (len != 4) goto invalid;
                ND_PRINT((ndo, " %s", format_32(value)));
            }
        }
            break;

        case DNCP_NODE_ENDPOINT: {
            if (!ndo->ndo_vflag)
                ND_PRINT((ndo, ", Node endpoint"));
            else {
                ND_PRINT((ndo, "\n\tNode endpoint"));
                if (len != 8) goto invalid;
                ND_PRINT((ndo, " %s", format_32(value)));
                ND_PRINT((ndo, " %d", EXTRACT_32BITS(value + 4)));
            }
        }
            break;

        case DNCP_NETWORK_STATE: {
            if (!ndo->ndo_vflag)
                ND_PRINT((ndo, ", Network state"));
            else {
                ND_PRINT((ndo, " "));
            }
        }
            break;

        case DNCP_NODE_STATE: {
            if (!ndo->ndo_vflag)
                ND_PRINT((ndo, ", Node state"));
            else {
                ND_PRINT((ndo, " "));
            }
        }
            break;

        case DNCP_PEER: {
            if (!ndo->ndo_vflag)
                ND_PRINT((ndo, ", Peer"));
            else {
                ND_PRINT((ndo, "\n\tPeer"));
                if (len <= 8) goto invalid;
                ND_PRINT((ndo, " %s %d %d",
                    format_32(value),
                    EXTRACT_32BITS(value + 4),
                    EXTRACT_32BITS(value + 8)
                ));
            }
        }
            break;

        case DNCP_KEEP_ALIVE_INTERVAL: {
            if (!ndo->ndo_vflag)
                ND_PRINT((ndo, ", Keep-alive interval"));
            else {
                ND_PRINT((ndo, "\n\tKeep-alive interval"));
                if (len < 8) goto invalid;
                ND_PRINT((ndo, " %d %d",
                    EXTRACT_32BITS(value),
                    EXTRACT_32BITS(value + 4)
                ));
            }
        }
            break;

        case DNCP_TRUST_VERDICT: {
            if (!ndo->ndo_vflag)
                ND_PRINT((ndo, ", Trust-Verdict"));
            else {
                ND_PRINT((ndo, "\n\tTrust-Verdict"));
                if (len <= 36) goto invalid;
                ND_PRINT((ndo, " %d %x",
                    *value,

                ))
            }
        }
            break;

        case HNCP_VERSION: {
            if (!ndo->ndo_vflag)
                ND_PRINT((ndo, ", HNCP-Version"));
            else {
                ND_PRINT((ndo, " "));
            }
        }
            break;

        case HNCP_EXTERNAL_CONNECTION: {
            if (!ndo->ndo_vflag)
                ND_PRINT((ndo, ", External-Connection"));
            else {
                ND_PRINT((ndo, " "));
            }
        }
            break;

        case HNCP_DELEGATED_PREFIX: {
            if (!ndo->ndo_vflag)
                ND_PRINT((ndo, ", Delegated-Prefix"));
            else {
                ND_PRINT((ndo, " "));
            }
        }
            break;

        case HNCP_PREFIX_POLICY: {
            if (!ndo->ndo_vflag)
                ND_PRINT((ndo, ", Prefix-Policy"));
            else {
                ND_PRINT((ndo, " "));
            }
        }
            break;

        case HNCP_DHCPV6_DATA: {
            if (!ndo->ndo_vflag)
                ND_PRINT((ndo, ", DHCPv6-Data"));
            else {
                ND_PRINT((ndo, " "));
            }
        }
            break;

        case HNCP_DHCPV4_DATA: {
            if (!ndo->ndo_vflag)
                ND_PRINT((ndo, ", DHCPv4-Data"));
            else {
                ND_PRINT((ndo, " "));
            }
        }
            break;

        case HNCP_ASSIGNED_PREFIX: {
            if (!ndo->ndo_vflag)
                ND_PRINT((ndo, ", Assigned-Prefix"));
            else {
                ND_PRINT((ndo, " "));
            }
        }
            break;

        case HNCP_NODE_ADDRESS: {
            if (!ndo->ndo_vflag)
                ND_PRINT((ndo, ", Node-Address"));
            else {
                ND_PRINT((ndo, " "));
            }
        }
            break;

        case HNCP_DNS_DELEGATED_ZONE: {
            if (!ndo->ndo_vflag)
                ND_PRINT((ndo, ", DNS-Delegated-Zone"));
            else {
                ND_PRINT((ndo, " "));
            }
        }
            break;

        case HNCP_DOMAIN_NAME: {
            if (!ndo->ndo_vflag)
                ND_PRINT((ndo, ", Domain-Name"));
            else {
                ND_PRINT((ndo, " "));
            }
        }
            break;

        case HNCP_NODE_NAME: {
            if (!ndo->ndo_vflag)
                ND_PRINT((ndo, ", Node-Name"));
            else {
                ND_PRINT((ndo, " "));
            }
        }
            break;

        case HNCP_MANAGED_PSK: {
            if (!ndo->ndo_vflag)
                ND_PRINT((ndo, ", Managed-PSK"));
            else {
                ND_PRINT((ndo, " "));
            }
        }
            break;

        default:
            ND_PRINT((ndo, "\n\tUnknown message type %d", type));
        }

        /*
        ND_PRINT((ndo, " %d (%d)", type, len));
        for (int a=0; a<len; a++) {
            ND_PRINT((ndo, " %02hhX", *(tlv+4+a) ));
        }
        //*/
        i += len + 4;
    }
    return;

 trunc:
    ND_PRINT((ndo, " %s", tstr));
    return;

 invalid:
    ND_PRINT((ndo, "%s", istr));
    return;
}
