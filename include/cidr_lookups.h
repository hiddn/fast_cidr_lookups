#ifndef __CIDR_LOOKUPS_H
#define __CIDR_LOOKUPS_H

#include <sys/types.h>
#include "irc_stuff.h"

typedef struct _cidr_node {
    struct irc_in_addr ip;
    unsigned char bits;
    struct _cidr_node *parent;
    struct _cidr_node *l;
    struct _cidr_node *r;
    char has_data;
    void *data;
} cidr_node;

typedef struct _cidr_root_node {
    struct _cidr_node *ipv4;
    struct _cidr_node *ipv6;
} cidr_root_node;


void DEBUG (char const *format, ...);
cidr_node* cidr_create_node(const struct irc_in_addr *ip, const unsigned char bits, const unsigned char has_data, void *data);
cidr_root_node* cidr_new_tree();
cidr_node* cidr_add_node(const cidr_root_node *root_tree, const char *cidr_string_format, void *data);
cidr_node* cidr_find_node(cidr_root_node *root_tree, char *cidr_string_format);
int cidr_rem_node_by_cidr(cidr_root_node *root_tree, char *cidr_string_format);
int cidr_rem_node(cidr_node *node);
void *cidr_get_data(cidr_root_node *root_tree, char *cidr_string_format);
unsigned short _cidr_get_bit(const struct irc_in_addr *ip1, unsigned int bitlen);
void _cidr_set_bit(struct irc_in_addr *ip1, unsigned char bitlen);
cidr_node* cidr_get_parent_node(cidr_root_node *root_tree, char *cidr_string_format);
const char* get_cidr_mask(cidr_node *node);
void set_cidr_mask(cidr_node *node, char *buf);

#endif /* __CIDR_LOOKUPS_H */