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
#define DNCP_NETWORK_NODE_STATE 5
#define DNCP_PEER 8
#define DNCP_KEEP_ALIVE_INTERVAL 9
#define DNCP_TRUST_VERDICT 10

/*
static const struct tok dncp_type_values[] = {
    { DNCP_REQUEST_NETWORK_STATE,	"Request network state" },
    { DNCP_REQUEST_NODE_STATE,		"Request node state" },
    { DNCP_NODE_ENDPOINT,		"Node endpoint" },
    { DNCP_NETWORK_STATE,		"Network state" },
    { DNCP_NETWORK_NODE_STATE,		"Network node state" },
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

void
hncp_print(netdissect_options *ndo,
           const u_char *cp, u_int length)
{
    ND_PRINT((ndo, "hncp"));

    u_int i = 0;
    while(i < length) {
        const u_char *tlv = cp + i;
        ND_TCHECK2(*tlv, 4);
        const u_short type = EXTRACT_16BITS(tlv);
        const u_short len = EXTRACT_16BITS(tlv + 2);
        ND_TCHECK2(*tlv, 4 + len);

        /*
        if (ndo->ndo_vflag < 1) {
            ND_PRINT((ndo, ", %s", tok2str(dncp_type_values, "unknown", type)));
            i += len + 4;
            continue;
        }
        */

        switch (type) {
        case DNCP_REQUEST_NETWORK_STATE: {
        }
            break;

        case DNCP_REQUEST_NODE_STATE: {
        }
            break;

        case DNCP_NODE_ENDPOINT: {
        }
            break;

        case DNCP_NETWORK_STATE: {
        }
            break;

        case DNCP_NETWORK_NODE_STATE: {
        }
            break;

        case DNCP_PEER: {
        }
            break;

        case DNCP_KEEP_ALIVE_INTERVAL: {
        }
            break;

        case DNCP_TRUST_VERDICT: {
        }
            break;

        case HNCP_VERSION: {
        }
            break;

        case HNCP_EXTERNAL_CONNECTION: {
        }
            break;

        case HNCP_DELEGATED_PREFIX: {
        }
            break;

        case HNCP_PREFIX_POLICY: {
        }
            break;

        case HNCP_DHCPV6_DATA: {
        }
            break;

        case HNCP_DHCPV4_DATA: {
        }
            break;

        case HNCP_ASSIGNED_PREFIX: {
        }
            break;

        case HNCP_NODE_ADDRESS: {
        }
            break;

        case HNCP_DNS_DELEGATED_ZONE: {
        }
            break;

        case HNCP_DOMAIN_NAME: {
        }
            break;

        case HNCP_NODE_NAME: {
        }
            break;

        case HNCP_MANAGED_PSK: {
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
}
