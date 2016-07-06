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
format_32(const unsigned char *data) //FIXME -> format_id() ?
{
    static char buf[4][11+5];
    static int i = 0;
    i = (i + 1) % 4;
    snprintf(buf[i], 16, "%02x:%02x:%02x:%02x",
             data[0], data[1], data[2], data[3]);
    return buf[i];
}

static const char * //FIXME usefull ?
format_64(const unsigned char *data)
{
    static char buf[4][23+5];
    static int i = 0;
    i = (i + 1) % 4;
    snprintf(buf[i], 28, "%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x",
             data[0], data[1], data[2], data[3],
             data[4], data[5], data[6], data[7]);
    return buf[i];
}

static const char *
format_256(const unsigned char *data)
{
    static char buf[4][64+5];
    static int i = 0;
    i = (i + 1) % 4;
    snprintf(buf[i], 28, "%016lx%016lx%016lx%016lx",
         EXTRACT_64BITS(data),
         EXTRACT_64BITS(data + 8),
         EXTRACT_64BITS(data + 16),
         EXTRACT_64BITS(data + 24)
    );
    return buf[i];
}

static const char *
format_interval(const uint16_t i)
{
    static char buf[sizeof("000.00s")];

    if (i == 0)
        return "0.0s (bogus)";
    snprintf(buf, sizeof(buf), "%u.%02us", i / 100, i % 100);
    return buf;
}

static void
hncp_print_rec(netdissect_options *ndo,
               const u_char *cp, u_int length, int indent);

void
hncp_print(netdissect_options *ndo,
           const u_char *cp, u_int length)
{
    ND_PRINT((ndo, "hncp (%d)", length));
    hncp_print_rec(ndo, cp, length, 1);
}

static void
hncp_print_rec(netdissect_options *ndo,
               const u_char *cp, u_int length, int indent)
{
    u_int i = 0;
    while (i < length) {
        const u_char *tlv = cp + i;
        ND_TCHECK2(*tlv, 4);
        const uint16_t type = EXTRACT_16BITS(tlv);
        const uint16_t len = EXTRACT_16BITS(tlv + 2);
        const u_char *value = tlv + 4;
        ND_TCHECK2(*value, len);

        if (!ndo->ndo_vflag) {
            if (i) ND_PRINT((ndo, ", "));
            else ND_PRINT((ndo, " "));
        } else {
            ND_PRINT((ndo, "\n"));
            for (int t=indent; t>0; t--) ND_PRINT((ndo, "\t"));
        }

        switch (type) {
        case DNCP_REQUEST_NETWORK_STATE: {
            if (!ndo->ndo_vflag)
                ND_PRINT((ndo, "Request network state"));
            else {
                ND_PRINT((ndo, "Request network state (%u)", len+4));
            }
        }
            break;

        case DNCP_REQUEST_NODE_STATE: {
            if (!ndo->ndo_vflag)
                ND_PRINT((ndo, "Request node state"));
            else {
                ND_PRINT((ndo, "Request Node state (%u)", len+4));
                if (len != 4) goto invalid;
                ND_PRINT((ndo, " NID: %s", format_32(value)));
            }
        }
            break;

        case DNCP_NODE_ENDPOINT: {
            if (!ndo->ndo_vflag)
                ND_PRINT((ndo, "Node endpoint"));
            else {
                ND_PRINT((ndo, "Node endpoint (%u)", len+4));
                if (len != 8) goto invalid;
                ND_PRINT((ndo, " NID: %s EPID: %08x",
                    format_32(value),
                    EXTRACT_32BITS(value + 4)
                ));
            }
        }
            break;

        case DNCP_NETWORK_STATE: {
            if (!ndo->ndo_vflag)
                ND_PRINT((ndo, "Network state"));
            else {
                ND_PRINT((ndo, "Network state (%u)", len+4));
                if (len != 8) goto invalid;
                ND_PRINT((ndo, " Hash: %016lx",
                    EXTRACT_64BITS(value)
                ));
            }
        }
            break;

        case DNCP_NODE_STATE: {
            if (!ndo->ndo_vflag)
                ND_PRINT((ndo, "Node state"));
            else {
                ND_PRINT((ndo, "Node state (%u)", len+4));
                if (len < 20) goto invalid;
                ND_PRINT((ndo, " NID: %s Seq-num: %u Interval: %s Hash: %016lx",
                    format_32(value),
                    EXTRACT_32BITS(value + 4),
                    format_interval(EXTRACT_32BITS(value + 8)),
                    EXTRACT_64BITS(value + 12)
                ));
                if (len > 20) {
                    ND_PRINT((ndo, " Data:"));

                    //*
                    int i = 20; // PRINT NESTED TLVs
                    while (i<len) {
                        const uint16_t type = EXTRACT_16BITS(value+i);
                        const uint16_t len = EXTRACT_16BITS(value+i + 2);
                        ND_PRINT((ndo, "\n\t\t%04x %04x ", type, len));
                        //ND_PRINT((ndo, "\n\t\t%02x%02x %02x%02x ", value[i], value[i+1], value[i+2], value[i+3] ));
                        for (int j = 0; j < len; j++) {
                            ND_PRINT((ndo, "%02x", value[i+4+j]));
                        }
                        i += len+4;
                    }
                    //*/

                    hncp_print_rec(ndo, value+20, len-20, indent+1);
                }
            }
        }
            break;

        case DNCP_PEER: {
            if (!ndo->ndo_vflag)
                ND_PRINT((ndo, "Peer"));
            else {
                ND_PRINT((ndo, "Peer (%u)", len+4));
                if (len != 12) goto invalid;
                ND_PRINT((ndo, " Peer-NID: %s Peer-EPID: %08x EPID: %08x",
                    format_32(value),
                    EXTRACT_32BITS(value + 4),
                    EXTRACT_32BITS(value + 8)
                ));
            }
        }
            break;

        case DNCP_KEEP_ALIVE_INTERVAL: {
            if (!ndo->ndo_vflag)
                ND_PRINT((ndo, "Keep-alive interval"));
            else {
                ND_PRINT((ndo, "Keep-alive interval (%u)", len+4));
                if (len < 8) goto invalid;
                ND_PRINT((ndo, " EPID: %08x Interval: %s",
                    EXTRACT_32BITS(value),
                    format_interval(EXTRACT_32BITS(value + 4))
                ));
            }
        }
            break;

        case DNCP_TRUST_VERDICT: {
            if (!ndo->ndo_vflag)
                ND_PRINT((ndo, "Trust-Verdict"));
            else {
                ND_PRINT((ndo, "Trust-Verdict (%u)", len+4));
                if (len <= 36) goto invalid;
                ND_PRINT((ndo, " Verdict: %d Fingerprint: %s common-name: ",
                    *value, // Verdict
                    // EXTRACT_24BITS(value + 1), // Reserved
                    format_256(value + 4) // Fingerprint
                ));
                for (int i = 36; i < length; i++) // Common Name
                    ND_PRINT((ndo, "%x", value[i]));
            }
        }
            break;

        case HNCP_VERSION: {
            if (!ndo->ndo_vflag)
                ND_PRINT((ndo, "HNCP-Version"));
            else {
                ND_PRINT((ndo, "HNCP-Version (%u)", len+4));
                if (len < 5) goto invalid;
                ND_PRINT((ndo, ""));
            }
        }
            break;

        case HNCP_EXTERNAL_CONNECTION: {
            if (!ndo->ndo_vflag)
                ND_PRINT((ndo, "External-Connection"));
            else {
                ND_PRINT((ndo, "External-Connection (%u)", len+4));
            }
        }
            break;

        case HNCP_DELEGATED_PREFIX: {
            if (!ndo->ndo_vflag)
                ND_PRINT((ndo, "Delegated-Prefix"));
            else {
                ND_PRINT((ndo, "Delegated-Prefix (%u)", len+4));
            }
        }
            break;

        case HNCP_PREFIX_POLICY: {
            if (!ndo->ndo_vflag)
                ND_PRINT((ndo, "Prefix-Policy"));
            else {
                ND_PRINT((ndo, "Prefix-Policy (%u)", len+4));
            }
        }
            break;

        case HNCP_DHCPV6_DATA: {
            if (!ndo->ndo_vflag)
                ND_PRINT((ndo, "DHCPv6-Data"));
            else {
                ND_PRINT((ndo, "DHCPv6-Data (%u)", len+4));
            }
        }
            break;

        case HNCP_DHCPV4_DATA: {
            if (!ndo->ndo_vflag)
                ND_PRINT((ndo, "DHCPv4-Data"));
            else {
                ND_PRINT((ndo, "DHCPv4-Data (%u)", len+4));
            }
        }
            break;

        case HNCP_ASSIGNED_PREFIX: {
            if (!ndo->ndo_vflag)
                ND_PRINT((ndo, "Assigned-Prefix"));
            else {
                ND_PRINT((ndo, "Assigned-Prefix (%u)", len+4));
            }
        }
            break;

        case HNCP_NODE_ADDRESS: {
            if (!ndo->ndo_vflag)
                ND_PRINT((ndo, "Node-Address"));
            else {
                ND_PRINT((ndo, "Node-Address (%u)", len+4));
            }
        }
            break;

        case HNCP_DNS_DELEGATED_ZONE: {
            if (!ndo->ndo_vflag)
                ND_PRINT((ndo, "DNS-Delegated-Zone"));
            else {
                ND_PRINT((ndo, "DNS-Delegated-Zone (%u)", len+4));
            }
        }
            break;

        case HNCP_DOMAIN_NAME: {
            if (!ndo->ndo_vflag)
                ND_PRINT((ndo, "Domain-Name"));
            else {
                ND_PRINT((ndo, "Domain-Name (%u)", len+4));
            }
        }
            break;

        case HNCP_NODE_NAME: {
            if (!ndo->ndo_vflag)
                ND_PRINT((ndo, "Node-Name"));
            else {
                ND_PRINT((ndo, "Node-Name (%u)", len+4));
            }
        }
            break;

        case HNCP_MANAGED_PSK: {
            if (!ndo->ndo_vflag)
                ND_PRINT((ndo, "Managed-PSK"));
            else {
                ND_PRINT((ndo, "Managed-PSK (%u)", len+4));
            }
        }
            break;

        default:
            if (768 <= type && type <= 1023) {
                if (!ndo->ndo_vflag)
                    ND_PRINT((ndo, "Unknown user-defined message"));
                else {
                    ND_PRINT((ndo, "Unknown user-defined message - type %u (%u)", type, len+4));
                }
            } else {
                if (!ndo->ndo_vflag)
                    ND_PRINT((ndo, "Unknown message type"));
                else {
                    ND_PRINT((ndo, "Unknown message type %u (%u)", type, len+4));
                }
            }
        }

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
