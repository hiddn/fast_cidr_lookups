#include <limits.h> /* for CHAR_BIT */
#include <stdio.h> /* for printf, snprintf */
#include <stdlib.h> /* for malloc, free, exit */
#include <assert.h> /* for assert */
#include <stdarg.h> /* for va_list, va_start, va_end */
#include "../include/cidr_lookups.h"
#include "../include/irc_stuff.h" /* for irc_in_addr, irc_in6_CIDRMinIP, ircd_ntocidrmask, ipmask_parse, irc_in_addr_is_ipv4, irc_in_addr_cmp */

#define MAX_DEBUG_PAYLOAD 2048

// local functions
static void DEBUG (char const *format, ...) __attribute__((format(printf, 1, 2)));
static cidr_node* _cidr_create_node(const struct irc_in_addr *ip, const unsigned char bits, const unsigned char is_virtual, void *data);
static cidr_node* _get_closest_parent_node(const cidr_node *node);

/** _cidr_bit_diff - find first mismatching bit
 * @param[in] node CIDR tree node to compare against
 * @param[in] ip Address to compare against the node
 * @param[in] lo First bit to compare (some bits 0..lo-1 might also be compared)
 * @param[in] hi One past the last bit to compare
 * @return Index of the first mismatch bit, \a hi if all bits match.
 */
unsigned char _cidr_bit_diff(const cidr_node *node, const struct irc_in_addr *ip, unsigned char lo, unsigned char hi)
{
    unsigned char lo_n = lo / 16;
    unsigned char hi_n = hi / 16;
    int ii;

    for (ii = lo_n; ii < hi_n; ++ii) {
        if (node->ip.in6_16[ii] != ip->in6_16[ii]) {
            int word = ntohs(node->ip.in6_16[ii] ^ ip->in6_16[ii]);
            return ii * 16 + __builtin_clz(word) + 16 - sizeof(int)*CHAR_BIT;
        }
    }

    if ((hi & 15) && (node->ip.in6_16[ii] != ip->in6_16[ii])) {
        int word = ntohs(node->ip.in6_16[ii] ^ ip->in6_16[ii]);
        word &= 0xffff0000 >> (hi & 15);
        if (word)
            return ii * 16 + __builtin_clz(word) + 16 - sizeof(int) * CHAR_BIT;
    }

    return hi;
}

/** cidr_new_tree - create a new CIDR tree
 * @return Pointer to the created CIDR tree root node
 */
cidr_root_node *cidr_new_tree()
{
    struct irc_in_addr ip;
    unsigned char bits;
    cidr_root_node *root = malloc(sizeof(cidr_root_node));
    assert(root != 0);
    if (!ipmask_parse("0.0.0.0/0", &ip, &bits))
        exit(-1);
    root->ipv4 = _cidr_create_node(&ip, bits, 1, 0);
    if (!ipmask_parse("0::/0", &ip, &bits))
        exit(-1);
    root->ipv6 = _cidr_create_node(&ip, bits, 1, 0);
    return root;
}

/** cidr_add_node - add a new node to the CIDR tree
 * @param[in] root_tree Pointer to the root of the CIDR tree
 * @param[in] cidr_string_format CIDR string format
 * @param[in] data Pointer to the data associated with the node
 * @return Pointer to the added CIDR node
 */
cidr_node *cidr_add_node(const cidr_root_node *root_tree, const char *cidr_string_format, void *data)
{
    unsigned short i = 0;
    cidr_node *n;
    cidr_node *new_node = 0;
    cidr_node *virtual_node = 0;
    cidr_node **child_pptr = 0;
    struct irc_in_addr ip;
    unsigned char bits;
    unsigned short turn_right = 0;
    if (!ipmask_parse(cidr_string_format, &ip, &bits)) {
        return 0;
    }
    irc_in6_CIDRMinIP(&ip, bits);
    char cidr[CIDR_LEN+1];
    strncpy(cidr, ircd_ntocidrmask(&ip, bits), CIDR_LEN);
    cidr[CIDR_LEN] = 0;
    DEBUG("add_node>    %s\tbits=%d\n", cidr, bits);
    n = irc_in_addr_is_ipv4(&ip) ? root_tree->ipv4 : root_tree->ipv6;
    for (i = 0; i < 128; ) {
        i = _cidr_bit_diff(n, &ip, i, (n->bits < bits) ? n->bits : bits);
        turn_right = (i < 128) ? _cidr_get_bit(&ip, i) : 0;
        DEBUG("\tdiff at %u of %u (%c)\n", i, n->bits, turn_right ? 'r' : 'l');
        assert((i <= n->bits) && (i <= bits));
        /* If pos == n->bits == bits, then we are updating n.
         * If pos == n->bits < bits, then we are setting a child of n.
         * If pos < n->bits, n needs a new parent:
         *  - If pos == bits, then the new node is n's new parent.
         *  - Otherwise (pos < bits), and we need a new virtual parent at pos.
         */
        if (i == n->bits) {
            if (i == bits) {
                // Update n itself.
                n->is_virtual = 0;
                n->data = data;
                return n;
            }
            /* Walk to one of n's children, if it exists. */
            child_pptr = turn_right ? &n->r : &n->l;
            if (!*child_pptr) {
                new_node = _cidr_create_node(&ip, bits, 0, data);
                new_node->parent = n;
                *child_pptr = new_node;
                return new_node;
            }
            n = *child_pptr;
        } else { /* i < n->bits */
            new_node = _cidr_create_node(&ip, bits, 0, data);
            if (i == bits) {
                /* Insert this node as n's parent. */
                new_node->parent = n->parent;
                *child_pptr = new_node;
                n->parent = new_node;
                child_pptr = _cidr_get_bit(&n->ip, i)
                    ? &new_node->r : &new_node->l;
                *child_pptr = n;
            } else {
                /* Insert virtual node above both new node and n. */
                virtual_node = _cidr_create_node(&ip, i, 1, NULL);
                virtual_node->parent = n->parent;
                *child_pptr = virtual_node;
                n->parent = virtual_node;
                new_node->parent = virtual_node;
                virtual_node->l = turn_right ? n : new_node;
                virtual_node->r = turn_right ? new_node : n;
            }
            return new_node;
        }
    }
    assert(0 && "fell off the edge");
    return 0;
}

/** _cidr_find_exact_node - find a node in the CIDR tree
 * @param[in] root_tree Pointer to the root of the CIDR tree
 * @param[in] cidr_string_format CIDR string format
 * @return Pointer to the found CIDR node, returns NULL if not found
 */
cidr_node *_cidr_find_exact_node(const cidr_root_node *root_tree, const char *cidr_string_format)
{
    return _cidr_find_node(root_tree, cidr_string_format, 1);
}

/** cidr_search_best - find a non-virtual node in the CIDR tree that covers the given CIDR string
 * @param[in] root_tree Pointer to the root of the CIDR tree
 * @param[in] cidr_string_format CIDR string format
 * @return Pointer to the found CIDR node, returns NULL if not found
 */
cidr_node *cidr_search_best(const cidr_root_node *root_tree, const char *cidr_string_format)
{
    return _cidr_find_node(root_tree, cidr_string_format, 0);
}

/** _cidr_find_node - find a non-virtual node in the CIDR tree that covers the given CIDR string
 * @param[in] root_tree Pointer to the root of the CIDR tree
 * @param[in] cidr_string_format CIDR string format
 * @param[in] is_exact_match If 1, look for an exact cidr_string match. Otherwise, get the closest matching node that covers the given CIDR string
 * @return Pointer to the found CIDR node, returns NULL if not found
 */
cidr_node *_cidr_find_node(const cidr_root_node *root_tree, const char *cidr_string_format, const unsigned short is_exact_match)
{
    unsigned short i = 0;
    cidr_node *n;
    cidr_node **child_pptr;
    struct irc_in_addr ip;
    unsigned char bits;
    unsigned short turn_right = 0;
    if (!ipmask_parse(cidr_string_format, &ip, &bits)) {
        return 0;
    }
    irc_in6_CIDRMinIP(&ip, bits);
    char cidr[CIDR_LEN+1];
    strncpy(cidr, ircd_ntocidrmask(&ip, bits), CIDR_LEN);
    n = irc_in_addr_is_ipv4(&ip) ? root_tree->ipv4 : root_tree->ipv6;
    for (i = n->bits; i <= 128; i++) {
        if (i >= bits) {
            if (!irc_in_addr_cmp(&ip, &n->ip) && i == n->bits)
                if (!n->is_virtual)
                    return n;
            if (is_exact_match)
                return 0;
            if (n->is_virtual)
                return _get_closest_parent_node(n);
            return n;
        }
        turn_right = _cidr_get_bit(&ip, i);
        child_pptr = turn_right ? &n->r : &n->l;
        if (!*child_pptr) {
            if (is_exact_match)
                return 0;
            if (n->is_virtual)
                return _get_closest_parent_node(n);
            return n;
        }
        n = *child_pptr;
        i += n->bits - n->parent->bits - 1;
    }
    assert(n != 0);
    return 0;
}

/** cidr_get_data - get data associated with a node in the CIDR tree
 * @param[in] root_tree Pointer to the root of the CIDR tree
 * @param[in] cidr_string_format CIDR string format
 * @return Pointer to the data associated with the node if it exists. Otherwise, returns NULL
 */
void *cidr_get_data(const cidr_root_node *root_tree, const char *cidr_string_format)
{
    cidr_node *node = _cidr_find_exact_node(root_tree, cidr_string_format);
    if (!node) {
        return 0;
    }
    return node->data;
}

/** cidr_rem_node_by_cidr - remove a node from the CIDR tree by CIDR string
 * @param[in] root_tree Pointer to the root of the CIDR tree
 * @param[in] cidr_string_format CIDR string format
 * @return 1 if the node was removed, 0 otherwise
 */
int cidr_rem_node_by_cidr(const cidr_root_node *root_tree, const char *cidr_string_format)
{
    return cidr_rem_node(_cidr_find_exact_node(root_tree, cidr_string_format));
}

/** cidr_rem_node - remove a node from the CIDR tree
 * @param[in] node Pointer to the node to be removed
 * @return 1 if the node was removed, 0 otherwise
 */
int cidr_rem_node(cidr_node *node)
{
    if (!node) {
        return 0;
    }
    if (node->is_virtual) {
        // Do not remove virtual nodes.
        return 0;
    }
    if (!node->parent) {
        // It is the root node. Make it virtual.
        node->is_virtual = 1;
        node->data = 0;
        return 1;
    }
    else if (node->l && node->r) {
        // Node has two children. Make it virtual.
        node->is_virtual = 1;
        node->data = 0;
        return 1;
    }
    else if ((node->l && !node->r) || (!node->l && node->r)) {
        // Node has only one children. Remove node and rearrange tree.
        cidr_node *child_node = node->l ? node->l : node->r;
        child_node->parent = node->parent;
        if (node->parent->l == node) {
            node->parent->l = node->l ? node->l : node->r;
        }
        else {
            node->parent->r = node->r ? node->r : node->l;
        }
    }
    else {
        // Node has no children. Remove node.
        if (node->parent->l == node) {
            node->parent->l = 0;
        }
        else {
            node->parent->r = 0;
        }
    }
    DEBUG("remove_node> %s\n", ircd_ntocidrmask(&node->ip, node->bits));
    // Check if parent node is virtual and has now only one children. If so, remove parent virtual node too.
    cidr_node *parent_node = node->parent;
    if (parent_node && parent_node->is_virtual && (!parent_node->l || !parent_node->r)) {
        cidr_node *grandparent_node = parent_node->parent;
        cidr_node *sibling_node = parent_node->l ? parent_node->l : parent_node->r;
        if (grandparent_node) {
            // Only free parent node if it's not the root node.
            if (grandparent_node->l == parent_node) {
                grandparent_node->l = sibling_node;
            } else {
                grandparent_node->r = sibling_node;
            }
            if (sibling_node) {
                sibling_node->parent = grandparent_node;
            }
            DEBUG("remove_node> %s\n", ircd_ntocidrmask(&node->ip, node->bits));
            free(parent_node);
            parent_node = grandparent_node;
        }
    }
    free(node);
    return 1;
}

/** get_cidr_mask - get the CIDR mask of a node
 *  Be careful: it returns a pointer to a static buffer that gets overwritten on each call
 * @param[in] node Pointer to the node
 * @return The CIDR mask of the node
 */
const char *get_cidr_mask(const cidr_node *node)
{
    return ircd_ntocidrmask(&node->ip, node->bits);
}

/** set_cidr_mask - copies the node's cidr mask to buffer buf
 * @param[in] node Pointer to the node
 * @param[out] buf Buffer to store the CIDR mask
 */
void set_cidr_mask(cidr_node *node, char *buf)
{
    assert(node != 0);
    const char *cidr = ircd_ntocidrmask(&node->ip, node->bits);
    strncpy(buf, cidr, CIDR_LEN);
    buf[CIDR_LEN] = 0;
}

/** _cidr_get_bit - get a specific bit from an IP address
 * @param[in] ip Pointer to the IP address
 * @param[in] bit_index Bit index - must be between 0 and 127
 * @return The specific bit from the IP address
 */
unsigned short _cidr_get_bit(const struct irc_in_addr *ip, const unsigned int bit_index)
{
    assert(bit_index < 128);
    unsigned int quot = (127 - bit_index) / 16;
	unsigned int rem = (127 - bit_index) % 16;
    unsigned short t = -1;
	if (bit_index == 0) {
        quot--;
    }
    unsigned short ip16 = ntohs(ip->in6_16[7-quot]);
    //DEBUG("\t\t\t\t [%3u] ip->in6_16[7-%u] = %-5u", bit_index, quot, ip16);
    ip16 &= (1 << (rem)) & t;
    //DEBUG(", %-5u\n", ip16);
    return ip16;
}

/** DEBUG - debug message handler
 * @param[in] format Format string
 * @param[in] ... Variable arguments
 */
static void DEBUG (char const *format, ...)
{
	va_list vl;
	int nchars;
	char outbuf[MAX_DEBUG_PAYLOAD+3];

#ifndef CIDR_DEBUG_ENABLED
    return;
#endif
	va_start(vl, format);
	nchars = vsnprintf(outbuf, MAX_DEBUG_PAYLOAD+1, format, vl);
	va_end(vl);
	if (nchars >= MAX_DEBUG_PAYLOAD) {
		DEBUG("Output truncated: ");
		nchars = MAX_DEBUG_PAYLOAD;
	}
    printf("%s", outbuf);
	return;
}

/** _cidr_create_node - create a new CIDR node
 * @param[in] ip IP address
 * @param[in] bits Number of bits in the CIDR mask
 * @param[in] is_virtual Flag indicating if the node is virtual
 * @param[in] data Pointer to the data associated with the node
 * @return Pointer to the created CIDR node
 */
static cidr_node *_cidr_create_node(const struct irc_in_addr *ip, const unsigned char bits, const unsigned char is_virtual, void *data)
{
    cidr_node *node = 0;
    assert(ip != 0);
    node = malloc(sizeof(cidr_node));
    memset(node, 0, sizeof(cidr_node));
    assert(node != 0);
    if (ip != 0)
        memcpy(&node->ip, ip, sizeof(node->ip));
    node->bits = bits;
    if (is_virtual) {
        node->is_virtual = 1;
    }
    node->data = data;
    return node;
}

static cidr_node *_get_closest_parent_node(const cidr_node *node)
{
    for (cidr_node *tmp_node = node->parent; tmp_node; tmp_node = tmp_node->parent) {
        if (tmp_node->is_virtual) {
            continue;
        }
        return tmp_node;
    }
    return 0;
}
