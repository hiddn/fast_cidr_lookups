/**
 * @file irc_stuff.h
 * Stuff taken from Undernet's ircu2: https://github.com/UndernetIRC/ircu2/
 */

#ifndef irc_in_addr_valid

#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>

#include "cidr_lookups.h" /* irc_in_addr */

#define SOCKIPLEN 45
#define CIDR_LEN 43

/** Evaluate to non-zero if \a ADDR is a valid address (not all 0s and not all 1s). */
#define irc_in_addr_valid(ADDR) (((ADDR)->in6_16[0] && ((ADDR)->in6_16[0]) != 65535) \
                                 || (ADDR)->in6_16[1] != (ADDR)->in6_16[0] \
                                 || (ADDR)->in6_16[2] != (ADDR)->in6_16[0] \
                                 || (ADDR)->in6_16[3] != (ADDR)->in6_16[0] \
                                 || (ADDR)->in6_16[4] != (ADDR)->in6_16[0] \
                                 || (ADDR)->in6_16[5] != (ADDR)->in6_16[0] \
                                 || (ADDR)->in6_16[6] != (ADDR)->in6_16[0] \
                                 || (ADDR)->in6_16[7] != (ADDR)->in6_16[0])
/** Evaluate to non-zero if \a ADDR (of type struct irc_in_addr) is an IPv4 address. */
#define irc_in_addr_is_ipv4(ADDR) (!(ADDR)->in6_16[0] && !(ADDR)->in6_16[1] && !(ADDR)->in6_16[2] \
                                   && !(ADDR)->in6_16[3] && !(ADDR)->in6_16[4] \
                                   && ((!(ADDR)->in6_16[5] && (ADDR)->in6_16[6]) \
                                       || (ADDR)->in6_16[5] == 65535))
/** Evaluate to non-zero if \a A is a different IP than \a B. */
#define irc_in_addr_cmp(A,B) (irc_in_addr_is_ipv4(A) ? ((A)->in6_16[6] != (B)->in6_16[6] \
                                  || (A)->in6_16[7] != (B)->in6_16[7] || !irc_in_addr_is_ipv4(B)) \
                              : memcmp((A), (B), sizeof(struct irc_in_addr)))



/* Created my own IsDigit. Did not take macro from ircu */
int IsDigit(char c);

extern const char* IpQuadTab[];

int ipmask_parse(const char *input, struct irc_in_addr *ip, unsigned char *pbits);
unsigned int ircd_aton_ip4(const char *input, unsigned int *output, unsigned char *pbits);
const char* ircd_ntoa_r(char* buf, const struct irc_in_addr* in);
const char* ircd_ntoa(const struct irc_in_addr* in);
const char* ircd_ntocidrmask(const struct irc_in_addr* in, const unsigned char bits);
void irc_in6_CIDRMinIP(struct irc_in_addr *ircip, unsigned int CClonesCIDR);





#endif /* irc_in_addr_valid */