#include <stdio.h>
#include <stdlib.h>
#include "../include/cidr_lookups.h"
#include "../include/irc_stuff.h"
#include <sys/types.h> /* BSD: for inet_addr */
#include <sys/socket.h> /* BSD, Linux: for inet_addr */
#include <netinet/in.h> /* BSD, Linux: for inet_addr */
#include <arpa/inet.h> /* BSD, Linux, Solaris: for inet_addr */
#include <assert.h>
#include <string.h>

//#define CIDR_DEBUG_ENABLED

struct _add_node_test_cases {
    char cidr[CIDR_LEN+1];
    char retval_expected;
} add_node_test_cases[] = {
    {"1.2.0.0/16", 1},
    {"1.2.3.4/31", 1},
    {"1.2.3.5/32", 1},
    {"1.2.3.4/31", 1},
    {"128.2.3.128/28", 1},
    {"128.2.4.0/28", 1},
    {"1.2.3.0/24", 1},
    {"1.2.3.0/31", 1},
    {"1.2.3.1/32", 1},
    {"1.2.3.2/31", 1},
    {"1.2.3.2/32", 1},
    {"1.2.3.0/29", 1},
    {"1.2.3.0/28", 1},
    {"1.2.3.128/29", 1},
    {"1.2.3.144/28", 1},
    {"1.2.3.128/25", 1},
};

struct _rem_node_test_cases {
    char cidr[CIDR_LEN+1];
    char retval_expected;
} rem_node_test_cases[] = {
    {"1.2.3.4/31", 1},
    {"1.2.0.0/16", 1},
    {"1.2.3.0/24", 1},
    {"0.0.0.0/0", 0},
    {"1.2.3.0/30", 0},
};


void walk_tree(const cidr_node *node, int uml_type) {
    static int noexist_inc = 0;
    static int depth = 0;
    char cidr[CIDR_LEN+1];
    char cidr_child_l[CIDR_LEN+1];
    char cidr_child_r[CIDR_LEN+1];
    cidr_node *child_node_l = 0;
    cidr_node *child_node_r = 0;
    if (!node) {
        return;
    }
    strncpy(cidr, ircd_ntocidrmask(&node->ip, node->bits), CIDR_LEN);
    cidr[CIDR_LEN] = 0;
    if (uml_type && depth == 0) {
        printf("\n@startuml\n");
        printf("agent \"%s%s\"\n", node && node->is_virtual ? "(v) " : "", cidr);
    }
    depth++;
    if (node->l) {
        child_node_l = node->l;
        strncpy(cidr_child_l, ircd_ntocidrmask(&child_node_l->ip, child_node_l->bits), CIDR_LEN);
        cidr_child_l[CIDR_LEN] = 0;
    }
    if (node->r) {
        child_node_r = node->r;
        strncpy(cidr_child_r, ircd_ntocidrmask(&child_node_r->ip, child_node_r->bits), CIDR_LEN);
        cidr_child_r[CIDR_LEN] = 0;
    }
    if (uml_type) {
        const char *cidr = ircd_ntocidrmask(&node->ip, node->bits);        
        if (node->l) {
            char turn = 'L';
            cidr_node *child_node;
            child_node = node->l;
            const char *cidr_child = cidr_child_l;
            const unsigned char skipped_bits = child_node->bits - child_node->parent->bits - 1;
            printf("agent \"%s%s\"\n", child_node && child_node->is_virtual ? "(v) " : "", cidr_child);
            char skip_str[32];
            if (child_node && child_node && skipped_bits)
                sprintf(skip_str, ": \"(%c) skip %u\"", turn, skipped_bits);
            else
                sprintf(skip_str, ": \"(%c)\"", turn);
            printf("\"%s%s\" -d-> \"%s%s\"%s\n",
                node && node->is_virtual ? "(v) " : "",
                cidr,
                child_node && child_node->is_virtual ? "(v) " : "",
                cidr_child,
                skip_str
                );
        }
        else if (node->r) {
            noexist_inc++;
            printf("agent \"NOEXIST_%d\" as NOEXIST_%d\n", noexist_inc, noexist_inc);
            printf("\"%s%s\" -[hidden]d-> \"NOEXIST_%d\"\n",
                node && node->is_virtual ? "(v) " : "",
                cidr,
                noexist_inc
                );
            printf("hide NOEXIST_%d\n", noexist_inc);
        }
        if (node->r) {
            char turn = 'R';
            cidr_node *child_node;
            child_node = node->r;
            const char *cidr_child = cidr_child_r;
            const unsigned char skipped_bits = child_node->bits - child_node->parent->bits - 1;
            printf("agent \"%s%s\"\n", child_node && child_node->is_virtual ? "(v) " : "", cidr_child);
            char skip_str[32];
            if (child_node && child_node && skipped_bits)
                sprintf(skip_str, ": \"(%c) skip %u\"", turn, skipped_bits);
            else
                sprintf(skip_str, ": \"(%c)\"", turn);
            printf("\"%s%s\" -d-> \"%s%s\"%s\n",
                node && node->is_virtual ? "(v) " : "",
                cidr,
                child_node && child_node->is_virtual ? "(v) " : "",
                cidr_child,
                skip_str
                );
        }
        else if (node->l) {
            noexist_inc++;
            printf("agent \"NOEXIST_%d\" as NOEXIST_%d\n", noexist_inc, noexist_inc);
            printf("\"%s%s\" -[hidden]d-> \"NOEXIST_%d\"\n",
                node && node->is_virtual ? "(v) " : "",
                cidr,
                noexist_inc
                );
            printf("hide NOEXIST_%d\n", noexist_inc);
        }
    }
    else {
        printf("node: %3s %-18s l: %3s %-18s r: %3s %-18s\n",
            node->is_virtual ? "(v)" : "",
            cidr,
            node->l && node->l->is_virtual ? "(v)" : "",
            node->l ? cidr_child_l : "",
            node->r && node->r->is_virtual ? "(v)" : "",
            node->r ? cidr_child_r : "");
    }
    walk_tree(node->l, uml_type);
    walk_tree(node->r, uml_type);
    depth--;
    if (depth == 0) {
        if (uml_type)
            printf("@enduml\n");
        printf("\n");
    }
}

unsigned short find_first_non_null_bit(const struct irc_in_addr *ip)
{
    unsigned char start_at;
    unsigned short t = -1;
    unsigned short bit_index = irc_in_addr_is_ipv4(ip) ? 96 : 0;
    start_at = irc_in_addr_is_ipv4(ip) ? 6 : 0;
    for (int i = start_at; i < 8; i++) {
        unsigned short ip16 = ntohs(ip->in6_16[i]);
        for (unsigned short rem = 16; rem > 0; rem--,bit_index++) {
            if (ip16 & (1 << (rem - 1)) & t)
                return bit_index;
        }
    }
    return bit_index - 1;
}

struct _test_cases_get_bit {
    char cidr[CIDR_LEN+1];
    unsigned char bitlen;
    unsigned short is_not_zero;
} tests_get_bit[] = {
    {"128.0.0.0/1", 96, 1},
    {"255.255.255.0/32", 127, 0},
    {"0.0.0.0/32", 127, 0},
    {"255.0.0.0/32", 127, 0},
    {"255.0.0.255/32", 127, 1},
    {"0.0.0.255/32", 127, 1},

    {"0.0.0.0/1", 96, 0},
    {"128.0.0.0/1", 96, 1},
    {"0.0.0.0/9", 105, 0},
    {"0.128.0.0/9", 104, 1},

    {"0.0.0.128/32", 120, 1},
    {"0.0.0.1/32", 127, 1},
    {"0.0.1.0/24", 119, 1},
    {"0.1.0.0/24", 111, 1},
    {"1.0.0.0/24", 103, 1},

    {"0.0.128.0/17", 112, 1},
    {"128.2.3.128/28", 96, 1},
};


int test__cidr_get_bit() {
    short func_success = 1;
    int array_size = sizeof(tests_get_bit) / sizeof(tests_get_bit[0]);
    printf("\nTesting test__cidr_get_bit\n");
    for (int i = 0; i < array_size; i++) {
        struct _test_cases_get_bit *test;
        struct irc_in_addr ip;
        unsigned char bits;
        unsigned short res;
        unsigned short success = 1;
        test = &tests_get_bit[i];
        ipmask_parse(test->cidr, &ip, &bits);
        printf("  [%3d] Case %18s  ", i, ircd_ntocidrmask(&ip, bits));
        irc_in6_CIDRMinIP(&ip, bits);
        res = _cidr_get_bit(&ip, test->bitlen);
        if ((test->is_not_zero && !res) || (!test->is_not_zero && res)) {
            success = 0;
            func_success = 0;
        }
        unsigned short first_bit_found_at = find_first_non_null_bit(&ip);
        printf("bit tested: %-3u  1st_bit: %3u   exp: %d   got: %d   res: %s\n", test->bitlen, first_bit_found_at, test->is_not_zero, res ? 1 : 0, success ? "SUCCESS" : "FAILED");
    }
    return func_success;
}

struct _test_cases_cidrminip {
    char cidr[CIDR_LEN+1];
    char exp_cidr[CIDR_LEN+1];
} tests_cidrminip[] = {
    {"255.255.255.255/16", "255.255.0.0/16"},
    {"255.255.255.255/17", "255.255.128.0/17"},
    {"255.255.255.255/18", "255.255.192.0/18"},
    {"255.255.255.255/15", "255.254.0.0/15"},
    {"255.255.255.255/14", "255.252.0.0/14"},
    {"255.255.255.255/32", "255.255.255.255/32"},
    {"255.255.255.255/31", "255.255.255.254/31"},
    {"255.255.255.255/1", "128.0.0.0/1"},
    {"255.255.255.255/0", "0.0.0.0/0"},
    {"128.2.4.0/28", "128.2.4.0/28"},
};

int test_irc_in6_CIDRMinIP() {
    short func_success = 1;
    int array_size = sizeof(tests_cidrminip) / sizeof(tests_cidrminip[0]);
    printf("\nTesting test_irc_in6_CIDRMinIP\n");
    for (int i = 0; i < array_size; i++) {
        struct _test_cases_cidrminip *test;
        struct irc_in_addr ip;
        unsigned char bits;
        unsigned short success = 1;

        test = &tests_cidrminip[i];
        ipmask_parse(test->cidr, &ip, &bits);
        irc_in6_CIDRMinIP(&ip, bits);
        if (strncmp(ircd_ntocidrmask(&ip, bits), test->exp_cidr, strlen(test->exp_cidr)) != 0) {
            success = 0;
            func_success = 0;
        }
        printf("  [%3d] Case %18s  exp: %-18s   got: %-18s   res: %s\n", i, test->cidr, test->exp_cidr, ircd_ntocidrmask(&ip, bits), success ? "SUCCESS" : "FAILED");
    }
    return func_success;
}


int test_cidr_add_node() {
    int success = 1;
    int array_size = sizeof(add_node_test_cases) / sizeof(add_node_test_cases[0]);
    cidr_root_node *root_tree = cidr_new_tree();
    
    for (int i = 0; i < array_size; i++) {
        cidr_add_node(root_tree, add_node_test_cases[i].cidr, 0);
    }
    cidr_node *node = root_tree->ipv4;
    printf("ipv4 tree:\n");
    walk_tree(node, 1);
    walk_tree(node, 0);
    printf("\nipv6 tree:\n");
    node = root_tree->ipv6;
    walk_tree(node, 1);
    walk_tree(node, 0);

    // Test cidr_find_node()
    printf("Testing cidr_find_node()...\n");
    for (int i = 0; i < array_size; i++) {
        cidr_node *node = cidr_find_node(root_tree, add_node_test_cases[i].cidr);
        const char *cidr = node ? ircd_ntocidrmask(&node->ip, node->bits) : 0;
        //char cidr[CIDR_LEN+1];
        //strcpy(cidr, ircd_ntocidrmask(&node->ip, node->bits));
        if (!node) {
            printf("  [%2d] %-18s   res: FAILED. node not found\n", i, add_node_test_cases[i].cidr);
            success = 0;
        }
        else if (strncmp(cidr, add_node_test_cases[i].cidr, strlen(add_node_test_cases[i].cidr)) != 0) {
            printf("  [%2d] %-18s   res: FAILED. node not identical: %s\n", i, add_node_test_cases[i].cidr, cidr);
            success = 0;
        }
        else {
            printf("  [%2d] %-18s   res: SUCCESS\n", i, add_node_test_cases[i].cidr);
        }
    }

    // Test cidr_rem_node()
    printf("\nTesting cidr_rem_node()...\n");
    array_size = sizeof(rem_node_test_cases) / sizeof(rem_node_test_cases[0]);
    for (int i = 0; i < array_size; i++) {
        cidr_rem_node_by_cidr(root_tree, rem_node_test_cases[i].cidr);
    }
    node = root_tree->ipv4;
    printf("ipv4 tree (after removing nodes):\n");
    walk_tree(node, 1);
    walk_tree(node, 0);
    printf("\nipv6 tree (after removing nodes):\n");
    node = root_tree->ipv6;
    walk_tree(node, 1);
    walk_tree(node, 0);

    printf("\n(Still) testing cidr_rem_node()...\n");
    for (int i = 0; i < array_size; i++) {
        cidr_node *node = cidr_find_node(root_tree, rem_node_test_cases[i].cidr);
        const char *cidr = node ? ircd_ntocidrmask(&node->ip, node->bits) : 0;
        if (node && !node->is_virtual) {
            printf("  [%2d] %-18s   res: FAILED. node was removed but was still found\n", i, rem_node_test_cases[i].cidr);
            success = 0;
        }
        else if (node && strncmp(cidr, rem_node_test_cases[i].cidr, strlen(rem_node_test_cases[i].cidr)) != 0) {
            printf("  [%2d] %-18s   res: FAILED. node not identical: %s\n", i, rem_node_test_cases[i].cidr, cidr);
            success = 0;
        }
        else {
            printf("  [%2d] %-18s   res: SUCCESS\n", i, rem_node_test_cases[i].cidr);
        }
    }
    return success;
}

int main() {
    int success = 1;
    int res;
    res = test_irc_in6_CIDRMinIP();
    if (!res)
        success = 0;
    res = test__cidr_get_bit();
    if (!res)
        success = 0;
    res = test_cidr_add_node();
    if (!res)
        success = 0;
    return !success;
}
