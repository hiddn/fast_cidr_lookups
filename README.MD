## fast_cidr_lookups
Fast IP to CIDR block(s) lookup using trie in c, inspired by [yl2chen's cidranger](https://github.com/yl2chen/cidranger) written in Golang, which was inspired by [IPv4 route lookup linux](https://vincent.bernat.im/en/blog/2017-ipv4-route-lookup-linux).


## Author
Hidden (hidden at undernet.org)

## How to use the library
Include the library headers
```c
#include "include/cidr_lookups.h"
#include "include/irc_stuff.h"
```

Create the root tree
```c
cidr_root_node *root_tree = cidr_new_tree();
```

Add the nodes with data ((char *) in this case, but can be of any type)
```c
cidr_node *node = 0;
char *str1 = "Data 1";
cidr_add_node(root_tree, "1.2.3.0/24", str1);
cidr_add_node(root_tree, "1.2.0.0/16", str1);
cidr_add_node(root_tree, "150.0.0.0/8", str1);
```

Search for the node that is the best match for an IP address and access its data.
```c
node = cidr_search_best(root_tree, "1.2.3.4");
if (node) {
    printf("Best match found for %s: node %s. Data: %s\n", ip, get_cidr_mask(node), (char *)node->data);
    // The best match for 1.2.3.4 is 1.2.3.0/24, as it is closer to 1.2.3.4/32 than 1.2.0.0/16.
}
```

Iterate all nodes that match an IP address
```c
cidr_node *iter_node = 0;
CIDR_SEARCH_ALL_MATCHES(root_tree, iter_node, "1.2.3.4") {
    printf("  Node %s. Data: %s\n", get_cidr_mask(iter_node), (char *)iter_node->data);
} CIDR_SEARCH_ALL_MATCHES_END;
// Results would be 1.2.3.0/24 and 1.2.0.0/16
```

To iterate all nodes
```c
cidr_node *i_node;
CIDR_ITER(root_tree, i_node) {
    printf("  Node %s. Data: %s\n", get_cidr_mask(i_node), (char *)i_node->data);
} CIDR_ITER_END;
```

Remove a node
```c
int is_rem_success = cidr_rem_node_by_cidr(root_tree, "1.2.0.0/16");
if (is_rem_success)
    printf("Sucessfully removed node 1.2.0.0/16\n");
```

## Full working example
See [example.c](example.c) for a complete working example.  

## Compile working example
```sh
make example
```

## Run test cases
```sh
make tests
```

## How a tree with a compressed path looks like
![tree](https://i.imgur.com/DwXoj0O.png)
The above tree is a plantuml generated by `make tests`
