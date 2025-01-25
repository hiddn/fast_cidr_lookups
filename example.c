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
    char *str_ptr;
    cidr_node *node;
    cidr_root_node *root_tree = cidr_new_tree();

    cidr_add_node(root_tree, "1234:5678:90ab:cdef::1/128", str1);
    cidr_add_node(root_tree, "1.2.3.0/24", str2);
    cidr_add_node(root_tree, "1.2.0.0/20", str3);
    cidr_add_node(root_tree, "1.2.3.4/32", str4);
    cidr_add_node(root_tree, "1.2.3.4/32", str5);  // This changes the data of the node (str4 -> str5)

    // Get the data directly
    str_ptr = (char *)cidr_get_data(root_tree, "1234:5678:90ab:cdef::1/128");
    if (str_ptr) {
        printf("Data for node 1234:5678:90ab:cdef::1/128: %s\n", str_ptr);
    }

    // Get node infos
    node = cidr_find_node(root_tree, "1.2.3.0/24");
    if (node) {
        str_ptr = (char *)node->data;
        char cidr[CIDR_LEN+1];
        set_cidr_mask(node, cidr);
        printf("Data for node %s: %s\n", cidr, str_ptr);
        node->data = str5;
        printf("Data for node %s: %s\n", cidr, str_ptr);
        char parent_cidr[CIDR_LEN+1];
        set_cidr_mask(node->parent, parent_cidr);
        printf("Node %s has parent %s\n", cidr, parent_cidr);
    }

    // Remove a node
    int is_rem_success = cidr_rem_node_by_cidr(root_tree, "1.2.0.0/20");
    if (is_rem_success)
        printf("Sucessfully removed node 1.2.0.0/20\n");
    node = cidr_find_node(root_tree, "1.2.0.0/20");
    if (!node) {
        printf("Node 1.2.0.0/20 not found. It was indeed removed.\n");
    }

    return 0;
}
