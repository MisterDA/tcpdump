#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <netdissect-stdinc.h>

#include <stdlib.h>

#include "netdissect.h"
#include "addrtoname.h"
#include "extract.h"

/* TLVs */
#define DNCP_RESERVED               0
#define DNCP_REQUEST_NETWORK_STATE  1
#define DNCP_REQUEST_NODE_STATE     2
#define DNCP_NODE_ENDPOINT          3
#define DNCP_NETWORK_STATE          4
#define DNCP_NODE_STATE             5
#define DNCP_PEER                   8
#define DNCP_KEEP_ALIVE_INTERVAL    9
#define DNCP_TRUST_VERDICT         10

#define HNCP_VERSION               32
#define HNCP_EXTERNAL_CONNECTION   33
#define HNCP_DELEGATED_PREFIX      34
#define HNCP_PREFIX_POLICY         43
#define HNCP_DHCPV4_DATA           37
#define HNCP_DHCPV6_DATA           38
#define HNCP_ASSIGNED_PREFIX       35
#define HNCP_NODE_ADDRESS          36
#define HNCP_DNS_DELEGATED_ZONE    39
#define HNCP_DOMAIN_NAME           40
#define HNCP_NODE_NAME             41
#define HNCP_MANAGED_PSK           42

#define RANGE_DNCP_RESERVED    0x10000
#define RANGE_HNCP_UNASSIGNED  0x10001
#define RANGE_DNCP_PRIVATE_USE 0x10002
#define RANGE_DNCP_FUTURE_USE  0x10003

static const struct tok type_values[] = {
    { DNCP_REQUEST_NETWORK_STATE, "Request network state" },
    { DNCP_REQUEST_NODE_STATE,    "Request node state" },
    { DNCP_NODE_ENDPOINT,         "Node endpoint" },
    { DNCP_NETWORK_STATE,         "Network state" },
    { DNCP_NODE_STATE,            "Network node state" },
    { DNCP_PEER,                  "Peer" },
    { DNCP_KEEP_ALIVE_INTERVAL,   "Keep-alive interval" },
    { DNCP_TRUST_VERDICT,         "Trust-Verdict" },

    { HNCP_VERSION,             "HNCP-Version" },
    { HNCP_EXTERNAL_CONNECTION, "External-Connection" },
    { HNCP_DELEGATED_PREFIX,    "Delegated-Prefix" },
    { HNCP_PREFIX_POLICY,       "Prefix-Policy" },
    { HNCP_DHCPV4_DATA,         "DHCPv4-Data" },
    { HNCP_DHCPV6_DATA,         "DHCPv6-Data" },
    { HNCP_ASSIGNED_PREFIX,     "Assigned-Prefix" },
    { HNCP_NODE_ADDRESS,        "Node-Address" },
    { HNCP_DNS_DELEGATED_ZONE,  "DNS-Delegated-Zone" },
    { HNCP_DOMAIN_NAME,         "Domain-Name" },
    { HNCP_NODE_NAME,           "Node-Name" },
    { HNCP_MANAGED_PSK,         "Managed-PSK" },

    { RANGE_DNCP_RESERVED,    "Reserved" },
    { RANGE_HNCP_UNASSIGNED,  "Unassigned" },
    { RANGE_DNCP_PRIVATE_USE, "Private use" },
    { RANGE_DNCP_FUTURE_USE,  "Future use" },

    { 0, NULL}
};

#define DH4_PAD 0
#define DH4_DNS_SERVERS 6
#define DH4_NTP_SERVERS 42

#define DH6OPT_DNS_SERVERS 23
#define DH6OPT_DOMAIN_LIST 24
#define DH6OPT_SNTP_SERVERS 31


static const char *
format_nid(const unsigned char *data)
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

static void dhcpv4_print(netdissect_options *ndo,
                       const u_char *cp, u_int length, int indent)
{
    u_int i = 0;

    while (i < length) {
        const u_char *tlv = cp + i;
        const uint8_t type = (uint8_t)tlv[0];
        const uint8_t bodylen = (uint8_t)tlv[1];
        const u_char *value = tlv + 2;

        safeputchar(ndo, '\n');
        for (int t=indent; t>0; t--)
            safeputchar(ndo, '\t');

        switch (type) {

        case DH4_DNS_SERVERS: {
            if (bodylen < 4 || bodylen % 4)
                // print error
                break;
            for (int i = 0; i < bodylen; i += 4)
                ND_PRINT((ndo, " %s", ipaddr_string(ndo, tlv + 1)));
        }
            break;
        } /* switch */
    } /* while */
}

static void dhcpv6_print(netdissect_options *ndo,
                       const u_char *cp, u_int length, int indent)
{
    u_int i = 0;

    while (i < length) {
        const u_char *tlv = cp + i;
        const uint16_t type = EXTRACT_16BITS(tlv);
        const uint16_t bodylen = EXTRACT_16BITS(tlv + 2);
        const u_char *value = tlv + 4;

        safeputchar(ndo, '\n');
        for (int t=indent; t>0; t--)
            safeputchar(ndo, '\t');

        switch (type) {
        } /* switch */
    } /* while */
}

void
hncp_print_rec(netdissect_options *ndo,
               const u_char *cp, u_int length, int indent)
{
    u_int i = 0;

    uint32_t last_type_mask = 0x10000;
    int last_type_count = -1;

    while (i < length) {
        const u_char *tlv = cp + i;
        ND_TCHECK2(*tlv, 4);
        if (i+4>length) goto invalid;

        const uint16_t type = EXTRACT_16BITS(tlv);
        const uint16_t bodylen = EXTRACT_16BITS(tlv + 2);
        const u_char *value = tlv + 4;
        ND_TCHECK2(*value, bodylen);  //TODO
        if (i+bodylen+4>length) goto invalid;

        uint32_t type_mask =
            (type==0)              ?RANGE_DNCP_RESERVED:
            (44<=type&&type<=511)  ?RANGE_HNCP_UNASSIGNED:
            (768<=type&&type<=1023)?RANGE_DNCP_PRIVATE_USE:
                                    type;
        {
            unsigned int i = 0;
            char flag = 1;
            while (1) {
                unsigned int key = type_values[i].v;
                if (key==type) {
                    flag = 0;
                    break;
                }
                if (key==0)
                    break;
                i++;
            }
            if (flag)
                type_mask = RANGE_DNCP_FUTURE_USE;
        }

        if (!ndo->ndo_vflag) {
            if (i)
                ND_PRINT((ndo, ","));
            ND_PRINT((ndo," %s",
                tok2str(type_values,"Easter Egg (42)",type_mask)
            ));
        } else {
            safeputchar(ndo, '\n');
            for (int t=indent; t>0; t--)
                safeputchar(ndo, '\t');
            ND_PRINT((ndo,"%s (%u)",
                tok2str(type_values,"Easter Egg (42)",type_mask),
                bodylen+4
            ));
        }

        switch (type_mask) {

        case DNCP_REQUEST_NETWORK_STATE: {
            if (ndo->ndo_vflag) {
                if (bodylen != 0) goto invalid;
                //TODO:HIDDEN BYTES
            }
        }
            break;

        case DNCP_REQUEST_NODE_STATE: {
            if (ndo->ndo_vflag) {
                if (bodylen != 4) goto invalid;
                ND_PRINT((ndo, " NID: %s", format_nid(value)));
            }
        }
            break;

        case DNCP_NODE_ENDPOINT: {
            if (ndo->ndo_vflag) {
                if (bodylen != 8) goto invalid;
                ND_PRINT((ndo, " NID: %s EPID: %08x",
                    format_nid(value),
                    EXTRACT_32BITS(value + 4)
                ));
            }
        }
            break;

        case DNCP_NETWORK_STATE: {
            if (ndo->ndo_vflag) {
                if (bodylen != 8) goto invalid;
                ND_PRINT((ndo, " Hash: %016lx",
                    EXTRACT_64BITS(value)
                ));
            }
        }
            break;

        case DNCP_NODE_STATE: {
            if (ndo->ndo_vflag) {
                if (bodylen < 20) goto invalid;
                ND_PRINT((ndo, " NID: %s Seq-num: %u Interval: %sms Hash: %016lx",
                    format_nid(value),
                    EXTRACT_32BITS(value + 4),
                    format_interval(EXTRACT_32BITS(value + 8)),
                    EXTRACT_64BITS(value + 12)
                ));
                if (bodylen > 20) {
                    ND_PRINT((ndo, " Data:"));
                    hncp_print_rec(ndo, value+20, bodylen-20, indent+1);
                }
            }
        }
            break;

        case DNCP_PEER: {
            if (ndo->ndo_vflag) {
                if (bodylen != 12) goto invalid;
                ND_PRINT((ndo, " Peer-NID: %s Peer-EPID: %08x Local-EPID: %08x",
                    format_nid(value),
                    EXTRACT_32BITS(value + 4),
                    EXTRACT_32BITS(value + 8)
                ));
            }
        }
            break;

        case DNCP_KEEP_ALIVE_INTERVAL: {
            if (ndo->ndo_vflag) {
                if (bodylen < 8) goto invalid;
                ND_PRINT((ndo, " EPID: %08x Interval: %s",
                    EXTRACT_32BITS(value),
                    format_interval(EXTRACT_32BITS(value + 4))
                ));
            }
        }
            break;

        case DNCP_TRUST_VERDICT: {
            if (ndo->ndo_vflag) {
                if (bodylen <= 36) goto invalid;
                ND_PRINT((ndo, " Verdict: %u Fingerprint: %s Common Name: ",
                    *value,
                    // EXTRACT_24BITS(value + 1), // Reserved
                    format_256(value + 4)));
                safeputs(ndo, value + 36, bodylen - 36);
            }
        }
            break;

        // FIXME: check the MPHL and the User-agent
        case HNCP_VERSION: {
            if (ndo->ndo_vflag) {
                uint16_t capabilities;
                uint8_t M, P, H, L;
                if (bodylen < 5) goto invalid;
                capabilities = EXTRACT_16BITS(value + 2);
                M = (uint8_t)((capabilities >> 12) & 0xf);
                P = (uint8_t)((capabilities >> 8) & 0xf);
                H = (uint8_t)((capabilities >> 4) & 0xf);
                L = (uint8_t)(capabilities & 0xf);
                ND_PRINT((ndo, " M: %u P: %u H: %u L: %u User-agent: ",
                    // EXTRACT_16BITS(value), // Reserved
                    M, P, H, L
                ));
                safeputs(ndo, value + 4, bodylen - 4);
            }
        }
            break;

        case HNCP_EXTERNAL_CONNECTION: {
            if (ndo->ndo_vflag) {
                hncp_print_rec(ndo, value, bodylen, indent+1);
            }
        }
            break;

        case HNCP_DELEGATED_PREFIX: {
            if (ndo->ndo_vflag) {
                uint8_t prefix_len;
                uint prefix_len_byte;
                if (bodylen < 9) goto invalid;
                prefix_len = value[4];
                prefix_len_byte = (prefix_len + 7) / 8;

                ND_PRINT((ndo, " VLSO: %s PLSO: %s Prefix: ",
                    format_interval(EXTRACT_32BITS(value)),
                    format_interval(EXTRACT_32BITS(value + 4))
                ));
                // FIXME: change prefix from (strange) string to IPv6 prefix
                //safeputs(ndo, value + 9, prefix_len_byte);
                char *buf = malloc(sizeof(char) * 23);
                decode_prefix6(ndo, value + 9, prefix_len_byte, buf, 23);
                safeputs(ndo, (const u_char*)buf, prefix_len_byte);
                free(buf);

                prefix_len_byte += 5;
                hncp_print_rec(ndo, value+prefix_len_byte, bodylen-prefix_len_byte, indent+1);
            }
        }
            break;

        case HNCP_PREFIX_POLICY: {
            if (ndo->ndo_vflag) {
                uint8_t policy;
                if (bodylen < 1) goto invalid;
                policy = value[0];
                ND_PRINT((ndo, " Type: "));
                if (policy == 0) {
                    if (bodylen != 1) goto invalid;
                    ND_PRINT((ndo, "Internet connectivity"));
                    //TODO:HIDDEN BYTES
                } else if (policy >= 1 && policy <= 128) {
                    ND_PRINT((ndo, "Dest-Prefix: ")); // TODO Prefix
                } else if (policy == 129) {
                    ND_PRINT((ndo, "DNS: "));
                } else if (policy == 130) {

                } else if (policy == 131) {
                    if (bodylen != 1) goto invalid;
                    ND_PRINT((ndo, "Restrictive assignment"));
                    //TODO:HIDDEN BYTES
                } else if (policy >= 132) {
                    ND_PRINT((ndo, "(invalid)"));// Reserved for future additions
                }
            }
        }
            break;

        // TODO
        case HNCP_DHCPV4_DATA: {
            if (ndo->ndo_vflag) {
                if (bodylen == 0) goto invalid;
            }
        }
            break;

        // TODO
        case HNCP_DHCPV6_DATA: {
            if (ndo->ndo_vflag) {
                if (bodylen == 0) goto invalid;
            }
        }
            break;

        case HNCP_ASSIGNED_PREFIX: {
            if (ndo->ndo_vflag) {
                uint8_t rsv, prty, prefix_len;
                uint prefix_len_byte;
                if (bodylen < 6) goto invalid;
                rsv = (uint8_t)((value[4] >> 4) & 0xf);
                prty = (uint8_t)(value[4] & 0xf);
                prefix_len = (uint8_t)value[5];
                prefix_len_byte = (prefix_len + 7) / 8;
                ND_PRINT((ndo, " EPID: %08x Rsv: %u Prty: %u Prefix bodylen: %u",
                    EXTRACT_32BITS(value),
                    rsv, prty, prefix_len
                ));
                if (prefix_len > 0) {
                    ND_PRINT((ndo, " Prefix: "));
                    // FIXME: change prefix from (strange) string to IPv6 prefix
                    // safeputs(ndo, value + 6, prefix_len_byte);
                    char *buf = malloc(sizeof(char) * 23);
                    decode_prefix6(ndo, value + 9, prefix_len_byte, buf, 23);
                    safeputs(ndo, (const u_char*)buf, prefix_len_byte);
                    free(buf);
                }

                hncp_print_rec(ndo, value + 6 + prefix_len_byte, bodylen - 6 - prefix_len_byte, indent+1);
            }
        }
            break;

        case HNCP_NODE_ADDRESS: {
            if (ndo->ndo_vflag) {
                if (bodylen < 20) goto invalid;
                ND_PRINT((ndo, " EPID: %08x IP Adress: %s",
                    EXTRACT_32BITS(value),
                    ip6addr_string(ndo, value + 4)
                ));

                hncp_print_rec(ndo, value + 20, bodylen - 20, indent+1);
            }
        }
            break;

        case HNCP_DNS_DELEGATED_ZONE: {
            if (ndo->ndo_vflag) {
                uint8_t rsv, L, B, S;
                if (bodylen < 17) goto invalid;
                rsv = (uint8_t)(value[16] & 0xf8);
                L = (uint8_t)((value[16] >> 2 & 0x1));
                B = (uint8_t)((value[16] >> 1 & 0x1));
                S = (uint8_t)(value[16] & 0x1);
                ND_PRINT((ndo, " IP-Adress: %s rsv: %d L: %d B: %d S: %d Zone: ",
                    ip6addr_string(ndo, value),
                    rsv, L, B, S
                ));
                // TODO
                // safeputs(ndo, value + 17, xxx);
                // hncp_print_rec(ndo, value + 17 + xxx, bodylen - 17 - xxx, indent+1);
            }
        }
            break;

        case HNCP_DOMAIN_NAME: {
            if (ndo->ndo_vflag) {
                if (bodylen == 0) goto invalid;
                ND_PRINT((ndo, " Domain: "));
                safeputs(ndo, value, bodylen);
            }
        }
            break;

        case HNCP_NODE_NAME: {
            if (ndo->ndo_vflag) {
                if (bodylen < 17) goto invalid;
                unsigned char l = value[16];
                if (bodylen < 17+l) goto invalid;
                ND_PRINT((ndo, " IP-Adress: %s Name: ",
                    ip6addr_string(ndo, value)
                ));
                if (l<64) {
                    safeputchar(ndo, '"');
                    safeputs(ndo,value+17,l);
                    safeputchar(ndo, '"');
                } else
                    ND_PRINT((ndo, "(invalid)"));
                l += 17;
                l += -l&3;
                if (bodylen>=l)
                    hncp_print_rec(ndo, value+l, bodylen-l, indent+1);
            }
        }
            break;

        case HNCP_MANAGED_PSK: {
            if (ndo->ndo_vflag) {
                if (bodylen < 32) goto invalid;
                ND_PRINT((ndo, " PSK: %s",
                    format_256(value)
                ));
                hncp_print_rec(ndo, value+32, bodylen-32, indent+1);
            }
        }
            break;

        case RANGE_DNCP_RESERVED: {
        }
            break;

        case RANGE_HNCP_UNASSIGNED: {
            if (ndo->ndo_vflag)
                ND_PRINT((ndo, " (type=%u)", type));
        }
            break;

        case RANGE_DNCP_PRIVATE_USE: {
            if (ndo->ndo_vflag)
                ND_PRINT((ndo, " (type=%u)", type));
            //TODO:HIDDEN BYTES
        }
            break;

        case RANGE_DNCP_FUTURE_USE: {
            if (ndo->ndo_vflag)
                ND_PRINT((ndo, " (type=%u)", type));
        }
    } /* switch */

        if (last_type_mask==type_mask)
            last_type_count++;
        else {
            last_type_mask = type_mask;
            last_type_count = 0;
        }

        i += 4 + bodylen + (-bodylen&3);
    }
    return;

 trunc:
    if (ndo->ndo_vflag) {
        ND_PRINT((ndo, "\n"));
        for (int t=indent; t>0; t--) ND_PRINT((ndo, "\t"));
    }
    ND_PRINT((ndo, "%s", "[|hncp]"));
    return;

 invalid:
    ND_PRINT((ndo, "%s", istr));
    return;
}
