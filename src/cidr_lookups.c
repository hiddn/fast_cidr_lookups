#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h> /* BSD: for inet_addr */
#include <sys/socket.h> /* BSD, Linux: for inet_addr */
#include <netinet/in.h> /* BSD, Linux: for inet_addr */
#include <arpa/inet.h> /* BSD, Linux, Solaris: for inet_addr */
#include <assert.h>
#include <time.h>
#include <stdarg.h>
#include "../include/cidr_lookups.h"
#include "../include/irc_stuff.h"

#define MAX_DEBUG_PAYLOAD 2048

/** DEBUG - debug message handler
 * @param[in] format Format string
 * @param[in] ... Variable arguments
 */
void DEBUG (char const *format, ...)
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

/** cidr_create_node - create a new CIDR node
 * @param[in] ip IP address
 * @param[in] bits Number of bits in the CIDR mask
 * @param[in] is_virtual Flag indicating if the node is virtual
 * @param[in] data Pointer to the data associated with the node
 * @return Pointer to the created CIDR node
 */
cidr_node* cidr_create_node(const struct irc_in_addr *ip, const unsigned char bits, const unsigned char is_virtual, void *data)
{
    cidr_node *node = 0;
    assert(ip != 0);
    node = malloc(sizeof(cidr_node));
    memset(node, 0, sizeof(cidr_node));
    assert(node != 0);
    if (ip != 0)
        memcpy(&node->ip, ip, sizeof(node->ip));
    node->bits = bits;
    if (!is_virtual) {
        node->is_virtual = 0;
    }
    node->data = data;
    return node;
}

/** cidr_new_tree - create a new CIDR tree
 * @return Pointer to the created CIDR tree root node
 */
cidr_root_node* cidr_new_tree()
{
    struct irc_in_addr ip;
    unsigned char bits;
    cidr_root_node *root = malloc(sizeof(cidr_root_node));
    assert(root != 0);
    if (!ipmask_parse("0.0.0.0/0", &ip, &bits))
        exit(-1);
    root->ipv4 = cidr_create_node(&ip, bits, 0, 0);
    if (!ipmask_parse("0::/0", &ip, &bits))
        exit(-1);
    root->ipv6 = cidr_create_node(&ip, bits, 0, 0);
    return root;
}

/** cidr_add_node - add a new node to the CIDR tree
 * @param[in] root_tree Pointer to the root of the CIDR tree
 * @param[in] cidr_string_format CIDR string format
 * @param[in] data Pointer to the data associated with the node
 * @return Pointer to the added CIDR node
 */
cidr_node* cidr_add_node(const cidr_root_node *root_tree, const char *cidr_string_format, void *data)
{
    unsigned short i = 0;
    cidr_node *n;
    cidr_node *new_node = 0;
    cidr_node *virtual_node = 0;
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
    cidr[CIDR_LEN] = 0;
    DEBUG("add_node>    %s\tbits=%d\n", cidr, bits);
    n = irc_in_addr_is_ipv4(&ip) ? root_tree->ipv4 : root_tree->ipv6;
    for (i = n->bits; i <= 128; i++) {
        if (i >= bits) {
            // We need to insert the new node under the n->parent node, but maybe not directly under.
            DEBUG(" \ti(%u) >= bits(%u)\n", i, bits);
            if (i == bits && !irc_in_addr_cmp(&ip, &n->ip)) {
                // Node already exists
                break;
            }
            new_node = cidr_create_node(&ip, bits, 1, data);
            virtual_node = 0;
            struct irc_in_addr tmp_ip;
            memcpy(&tmp_ip, &ip, sizeof(struct irc_in_addr));
            // Iterate between the parent's node and the current node to find the proper place to insert the node.
            // Considering that we skip bits, we may require to create a virtual node at some point.
            for (unsigned char j = n->parent->bits; j < bits; j++) {
                unsigned char ip_bit = _cidr_get_bit(&ip, j);
                unsigned char n_ip_bit = _cidr_get_bit(&n->ip, j);
                if (ip_bit == n_ip_bit) {
                    // As long as the bits are the same, we continue.
                    continue;
                }
                // Create a virtual node that holds no data.
                irc_in6_CIDRMinIP(&tmp_ip, j);
                virtual_node = cidr_create_node(&tmp_ip, j, 0, data);
                child_pptr = turn_right ? &n->parent->r : &n->parent->l;
                *child_pptr = virtual_node;
                virtual_node->parent = n->parent;
                virtual_node->l = ip_bit ? n : new_node;
                virtual_node->r = !ip_bit ? n : new_node;
                n->parent = virtual_node;
                new_node->parent = virtual_node;
                DEBUG("\tbit %3u node  %3s %-18s turn %s  (Virtual node created)\n", j, virtual_node->is_virtual ? "(v)" : "", ircd_ntocidrmask(&virtual_node->ip, virtual_node->bits), ip_bit ? "right" : "left");
            }
            if (!virtual_node) {
                child_pptr = turn_right ? &n->parent->r : &n->parent->l;
                *child_pptr = new_node;
                new_node->parent = n->parent;
                if (_cidr_get_bit(&n->ip, bits))
                    new_node->r = n;
                else
                    new_node->l = n;
                n->parent = new_node;
            }
            DEBUG("\tAdding node\n");
            return new_node;
        }
        turn_right = _cidr_get_bit(&ip, i);
        child_pptr = turn_right ? &n->r : &n->l;
        DEBUG("\tbit %3u node  %3s %-18s turn %s\n", i, n->is_virtual ? "(v)" : "", ircd_ntocidrmask(&n->ip, n->bits), turn_right ? "right" : "left");
        if (!*child_pptr || i == 128) {
            DEBUG("\tAdding node\n");
            new_node = cidr_create_node(&ip, bits, 1, data);
            *child_pptr = new_node;
            new_node->parent = n;
            return new_node;
        }
        n = *child_pptr;
        // Handle skipped bits
        i += n->bits - n->parent->bits - 1;
    }
    // The entry already exists, whether it's with a bitlen of 128 or lower
    DEBUG("i=%u\n", i);
    assert(i < 129);
    assert(i == bits);
    assert(n != 0);
    DEBUG("\tAlready exists? Current node: %s\n", ircd_ntocidrmask(&n->ip, n->bits));
    n->data = data;
    return n;
}

/** cidr_find_node - find a node in the CIDR tree
 * @param[in] root_tree Pointer to the root of the CIDR tree
 * @param[in] cidr_string_format CIDR string format
 * @return Pointer to the found CIDR node, returns NULL if not found
 */
cidr_node* cidr_find_node(const cidr_root_node *root_tree, const char *cidr_string_format)
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
    if (irc_in_addr_is_ipv4(&ip)) {
        n = root_tree->ipv4;
    }
    else
        n = root_tree->ipv6;
    for (i = n->bits; i <= 128; i++) {
        if (i >= bits) {
            if (!irc_in_addr_cmp(&ip, &n->ip) && i == n->bits)
                if (!n->is_virtual)
                    return n;
            return 0;
        }
        turn_right = _cidr_get_bit(&ip, i);
        child_pptr = turn_right ? &n->r : &n->l;
        if (!*child_pptr) {
            return 0;
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
    cidr_node *node = cidr_find_node(root_tree, cidr_string_format);
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
    return cidr_rem_node(cidr_find_node(root_tree, cidr_string_format));
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

/** get_cidr_mask - get the CIDR mask of a node
 *  Be careful: it returns a pointer to a static buffer that gets overwritten on each call
 * @param[in] node Pointer to the node
 * @return The CIDR mask of the node
 */
const char* get_cidr_mask(const cidr_node *node)
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
