#include <stdio.h>
#include <stdlib.h>
#include "include/cidr_lookups.h"
#include "include/irc_stuff.h"

int main()
{
    char *str1 = "Data 1";
    char *str2 = "Data 2";
    char *str3 = "Data 3";
    char *str4 = "Data 4";
    char *str5 = "New data";
    struct irc_in_addr ip;
    unsigned char nbits;
    const char *ip_text;
    cidr_node *node;
    cidr_root_node *root_tree = cidr_new_tree();

    // The data we add to the nodes is just a string here, but it could be any data structure
    ipmask_parse("1234:5678:90ab:cdef::1/128", &ip, &nbits);
    cidr_add_node(root_tree, &ip, nbits, str1);
    ipmask_parse("1.2.3.0/24", &ip, &nbits);
    cidr_add_node(root_tree, &ip, nbits, str2);
    ipmask_parse("1.2.0.0/20", &ip, &nbits);
    cidr_add_node(root_tree, &ip, nbits, str3);
    ipmask_parse("1.2.3.4/32", &ip, &nbits);
    cidr_add_node(root_tree, &ip, nbits, str4);
    ipmask_parse("1.2.3.4/32", &ip, &nbits);
    cidr_add_node(root_tree, &ip, nbits, str5);  // This changes the data of the node (str4 -> str5)

    // Search best match
    ipmask_parse("1.2.3.4", &ip, &nbits);
    ip_text = ircd_ntoa(&ip);
    printf("Searching best match for %s...\n", ip_text);
    node = cidr_search_best(root_tree, &ip, 128); // Note: for IPv4, add 96 to nbits. In this case, for a /32, we use 32+96 = 128.
    if (node) {
        printf("Best match found: node %s. Data: %s\n", get_cidr_mask(node), (char *)node->data);
    }
    // Output: Best match found for 1.2.3.4: node 1.2.3.4/32. Data: New data

    // Search all matches
    printf("\nSearching all matches for %s...\n", ip_text);
    cidr_node *iter_node = 0;
    CIDR_SEARCH_ALL_MATCHES(root_tree, iter_node, &ip) {
        printf("  Node %s. Data: %s\n", get_cidr_mask(iter_node), (char *)iter_node->data);
    } CIDR_SEARCH_ALL_MATCHES_END;
    /* Output:
        Node 1.2.3.4/32. Data: New data
        Node 1.2.3.0/24. Data: Data 2
        Node 1.2.0.0/20. Data: Data 3
    */
    printf("End of search\n\n");

    printf("Iterating through all nodes...\n");
    cidr_node *i_node;
    CIDR_ITER(root_tree, i_node) {
        printf("  Node %s. Data: %s\n", get_cidr_mask(i_node), (char *)i_node->data);
    } CIDR_ITER_END;
    /* Output:
        Node 1.2.0.0/20. Data: Data 3
        Node 1.2.3.0/24. Data: Data 2
        Node 1.2.3.4/32. Data: New data
        Node 1234:5678:90ab:cdef::1/128. Data: Data 1
    */
    printf("End of iteration\n\n");

    // Remove a node
    ipmask_parse("1.2.0.0/20", &ip, &nbits);
    int is_rem_success = cidr_rem_node_by_cidr(root_tree, &ip, nbits);
    if (is_rem_success)
        printf("Sucessfully removed node 1.2.0.0/20\n");
    node = _cidr_find_exact_node(root_tree, &ip, nbits);
    if (!node || !node->data) {
        // Virtual nodes are nodes that were not created by the user.
        // They hold no data, but are necessary for the tree structure.
        printf("Node 1.2.0.0/20 not found. It was indeed removed.\n");
    }

    return 0;
}
