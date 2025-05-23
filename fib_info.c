#include <net/flow.h>
#include <linux/seq_file.h>
#include <linux/rcupdate.h>
#include <net/fib_notifier.h>
#include <net/fib_rules.h>
#include <net/inetpeer.h>
#include <linux/percpu.h>
#include <linux/notifier.h>
#include <linux/refcount.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/inetdevice.h>
#include <linux/types.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <net/ip_fib.h>
#include <net/route.h>
#include <linux/rtnetlink.h>
#include <net/net_namespace.h>
#include <net/fib_rules.h> 
#include <linux/netfilter.h>
#include <linux/ip.h>
#include <net/ip_fib.h>


#define SELECT 2 // 1 for routes, 2 for device struct, 3 for the routing tables 


static void print_fib_info(struct fib_info *fi);
static int get_device_routes(struct net_device *dev);
static void print_route_info(struct fib_result *res);
static void analyze_routing_table(struct net *net);
static void try_fig_get_table(struct net *net);

const char *scope_to_string(unsigned char scope) {

    // there are more scope, these are scope that are for the user (distance to the destination)
    switch (scope) {
        case RT_SCOPE_UNIVERSE: return "Universe";
        case RT_SCOPE_SITE: return "Site";
        case RT_SCOPE_LINK: return "Link";
        case RT_SCOPE_HOST: return "Host";
        case RT_SCOPE_NOWHERE: return "Nowhere";
        default: return "Unknown";
    }
}

const char *fib_protocol_to_string(int proto){
    // this might be intresting in case of the router not so musch for the normal machine 
    switch (proto)
    {
    case RTPROT_UNSPEC : return "Not specified";
    case RTPROT_REDIRECT : return "Redirect";
    case RTPROT_KERNEL : return "Kernel";
    case RTPROT_BOOT : return "Boot";
    case RTPROT_STATIC : return "Static";   
    case RTPROT_DHCP : return "DHCP";
    case RTPROT_MROUTED : return "MROUTED";
    case RTPROT_BABEL : return "BABEL";
    case RTPROT_BGP : return "BGP";
    case RTPROT_ISIS : return "ISIS";
    case RTPROT_OSPF : return "OSPF";
    case RTPROT_RIP : return "RIP";
    case RTPROT_EIGRP : return "EIGRP";
    default: return "Unknown";
    }
}


void print_route_info(struct fib_result *res) {
    if (!res)
        return;

    printk(KERN_INFO "Route Information:\n");
    printk(KERN_INFO "  Prefix: %pI4/%u\n", &res->prefix, res->prefixlen);
    printk(KERN_INFO "  Type: %u\n", res->type);
    printk(KERN_INFO "  Scope: %u\n", res->scope);

    if (res->nhc) {
        printk(KERN_INFO "  Next Hop Cache Details:\n");
        printk(KERN_INFO "    Device: %s\n", res->nhc->nhc_dev ? 
               res->nhc->nhc_dev->name : "none");
        printk(KERN_INFO "    Gateway: %pI4\n", &res->nhc->nhc_gw.ipv4);
        printk(KERN_INFO "    Flags: 0x%x\n", res->nhc->nhc_flags);
        //printk(KERN_INFO "    Protocol: %u\n", res->nhc->nhc_protocol);
        printk(KERN_INFO "    Scope: %s (%u)\n", scope_to_string(res->nhc->nhc_scope), 
               res->nhc->nhc_scope);
        
        // Print interface index if device exists
        if (res->nhc->nhc_dev) {
            printk(KERN_INFO "    Interface Index: %d\n", res->nhc->nhc_dev->ifindex);
        }
        
        // Print OIF (output interface) if available
        if (res->fi) {
            printk(KERN_INFO "    OIF: %d\n", res->fi->fib_nh->fib_nh_oif);
        }
    }
}

static int get_device_routes(struct net_device *dev)
{
    struct fib_result res = {};
    struct flowi4 fl4 = {};
    struct net *net = dev_net(dev);
    
    // Set up flow parameters for lookup
    fl4.flowi4_oif = dev->ifindex;
    fl4.flowi4_scope = RT_SCOPE_UNIVERSE;
    
    // Perform FIB lookup
    if (fib_lookup(net, &fl4, &res, 0) == 0) {
        printk(KERN_INFO "Found route for device %s:\n", dev->name);
        if (res.fi) {
            print_fib_info(res.fi);
            print_route_info(&res);
        }
        return 0;
    } else {
        printk(KERN_ERR "No route found for device %s\n", dev->name);
    }
    
    return -ENOENT;
}

static void print_fib_info(struct fib_info *fi)
{
    int i;
    const char * proto ;
    
    if (!fi)
        return;

    proto =  fib_protocol_to_string(fi->fib_protocol);

    printk(KERN_INFO "FIB Info:\n");
    //if proto == x do this -> 
    if(strcmp(proto,"BGP") == 0){
        //get_bgp_info() // get info x 
    }else{
        printk(KERN_INFO "  Protocol: %s\n", fib_protocol_to_string(fi->fib_protocol));
    }
    printk(KERN_INFO "  Scope: %u\n", fi->fib_scope);
    printk(KERN_INFO "  Type: %u\n", fi->fib_type);
    printk(KERN_INFO "  Priority: %u\n", fi->fib_priority);
    
    // Print next hop information
    // this should be in a separated function ? 
    printk(KERN_INFO "  Next hops (%d):\n", fi->fib_nhs);
    for (i = 0; i < fi->fib_nhs; i++) {
        struct fib_nh *nh = &fi->fib_nh[i];
        printk(KERN_INFO "    NH%d: dev=%s gw=%pI4\n", 
               i,
               nh->fib_nh_dev ? nh->fib_nh_dev->name : "none",
               &nh->fib_nh_gw4);
    }
}

static void get_feature_dev(netdev_features_t *feat, char *name) {
    printk(KERN_INFO "Device features of %s\n", name);
    
    // Scatter/Gather I/O
    if (*feat & NETIF_F_SG)
        printk(KERN_INFO "NETIF_F_SG: Scatter/Gather I/O is supported\n");
    
    // Checksum Features
    if (*feat & NETIF_F_IP_CSUM)
        printk(KERN_INFO "NETIF_F_IP_CSUM: IPv4 checksum offload\n");
    if (*feat & NETIF_F_IPV6_CSUM)
        printk(KERN_INFO "NETIF_F_IPV6_CSUM: IPv6 checksum offload\n");
    if (*feat & NETIF_F_RXCSUM)
        printk(KERN_INFO "NETIF_F_RXCSUM: RX checksumming offload\n");
    
    // TCP/UDP Checksum Features
    if (*feat & NETIF_F_TSO)
        printk(KERN_INFO "NETIF_F_TSO: TCP Segmentation Offload\n");
    if (*feat & NETIF_F_GSO)
        printk(KERN_INFO "NETIF_F_GSO: Generic Segmentation Offload\n");
    
    // VLAN Features
    if (*feat & NETIF_F_HW_VLAN_CTAG_TX)
        printk(KERN_INFO "NETIF_F_HW_VLAN_CTAG_TX: Hardware VLAN tag insertion\n");
    if (*feat & NETIF_F_HW_VLAN_CTAG_RX)
        printk(KERN_INFO "NETIF_F_HW_VLAN_CTAG_RX: Hardware VLAN tag extraction\n");
    
    // Generic Features
    if (*feat & NETIF_F_HIGHDMA)
        printk(KERN_INFO "NETIF_F_HIGHDMA: High DMA memory support\n");
    if (*feat & NETIF_F_LOOPBACK)
        printk(KERN_INFO "NETIF_F_LOOPBACK: Loopback enabled\n");
    
    // TX/RX Features
    if (*feat & NETIF_F_GRO)
        printk(KERN_INFO "NETIF_F_GRO: Generic Receive Offload\n");
    if (*feat & NETIF_F_LRO)
        printk(KERN_INFO "NETIF_F_LRO: Large Receive Offload\n");
    
    // Ntuple filtering
    if (*feat & NETIF_F_NTUPLE)
        printk(KERN_INFO "NETIF_F_NTUPLE: N-tuple filtering support\n");
    
    // RX Hashing
    if (*feat & NETIF_F_RXHASH)
        printk(KERN_INFO "NETIF_F_RXHASH: RX hashing offload\n");
}

static void get_device_struct(struct net_device *dev){

    netdev_features_t *feat = &dev->features;
    printk(KERN_INFO "Device name: %s\n", dev->name);
    // this let you print the MAC address 
    printk(KERN_INFO "Device perm address: %pM\n", dev->perm_addr);
    printk(KERN_INFO "Device MTU: %d\n", dev->mtu);
    printk(KERN_INFO "Device flags: 0x%x\n", dev->flags);
    printk(KERN_INFO "Device type: %s\n", dev->type == ARPHRD_ETHER ? "Ethernet" : "Unknown");
    // intresting how perm addr and dev addr are the same -> i guess that you can change the mac but perm MAC keeps track of the old mac? what if i try to change it 
    // to note that for virtual bridge the mac 
    printk(KERN_INFO "Device dev addr: %pM\n", dev->dev_addr);
    printk(KERN_INFO "Device broadcast addr: %pM\n", dev->broadcast);
    printk(KERN_INFO "Device hard header len: %d\n", dev->hard_header_len);
    printk(KERN_INFO "Device addr len: %d\n", dev->addr_len);

    get_feature_dev(feat,dev->name);
}

/* 
 * Alternative implementation to try using fib_get_table 
 * We'll attempt to use it with appropriate error handling
 */
static void try_fig_get_table(struct net *net) {
    struct fib_table *tb = NULL;
    
    printk(KERN_INFO "Attempting to access routing table using fib_get_table\n");
    
#ifdef CONFIG_IP_MULTIPLE_TABLES
/*     // Only try this if multiple tables are supported
    tb = fib_get_table(net, RT_TABLE_MAIN);
    if (!tb) {
        printk(KERN_WARNING "fib_get_table returned NULL for main table\n");
        return;
    }
    
    printk(KERN_INFO "Successfully retrieved table ID: %u\n", tb->tb_id);
    // printk(KERN_INFO "Table type: %u\n", tb->tb_type);
    
    // Local table is often table ID 255
    tb = fib_get_table(net, RT_TABLE_LOCAL);
    if (tb) {
        printk(KERN_INFO "Local table ID: %u\n", tb->tb_id);
        //printk(KERN_INFO "Local table type: %u\n", tb->tb_type);
    }
    
    // Default table is often table ID 253
    tb = fib_get_table(net, RT_TABLE_DEFAULT);
    if (tb) {
        printk(KERN_INFO "Default table ID: %u\n", tb->tb_id);
        //printk(KERN_INFO "Default table type: %u\n", tb->tb_type);
    } */
#else
    printk(KERN_INFO "Multiple routing tables not supported in this kernel\n");
#endif
}

// Alternative approach using fib lookup - doesn't directly need fib_get_table
static void analyze_routing_table(struct net *net) {
    struct fib_result res;
    struct flowi4 fl4;
    __be32 test_ips[] = {
        // Some common destinations to test routing
        htonl(0x08080808),  // 8.8.8.8
        htonl(0x01010101),  // 1.1.1.1
        htonl(0x7f000001),  // 127.0.0.1
        htonl(0xC0A80101),  // 192.168.1.1
        htonl(0xC0A80001)   // 192.168.0.1
    };
    int i, ret;
    
    printk(KERN_INFO "Analyzing routing table by performing lookups\n");
    
    for (i = 0; i < ARRAY_SIZE(test_ips); i++) {
        memset(&fl4, 0, sizeof(fl4));
        fl4.daddr = test_ips[i];
        fl4.flowi4_scope = RT_SCOPE_UNIVERSE;
        
        printk(KERN_INFO "Looking up route for %pI4\n", &test_ips[i]);
        
        ret = fib_lookup(net, &fl4, &res, 0);
        if (ret == 0) {
            printk(KERN_INFO "Found route!\n");
            if (res.fi) {
                print_fib_info(res.fi);
            }
            print_route_info(&res);
        } else {
            printk(KERN_INFO "No route found (error: %d)\n", ret);
        }
        
        printk(KERN_INFO "-----------------------------\n");
    }
}

/* 
 * This function attempts to use netlink to get routing information.
 * It's a more standard way to access routing tables from both
 * kernel and user space.
 */
static void netlink_route_query(void) {
    // This is just a placeholder as full netlink implementation
    // would require significant additional code
    printk(KERN_INFO "For complete routing table access, netlink is recommended.\n");
    printk(KERN_INFO "Check documentation for rtnetlink_rcv and rtmsg structures.\n");
}

static int __init fib_info_init(void)
{
    struct net_device *dev;
    struct net *net = &init_net;
    
    printk(KERN_INFO "Loading enhanced FIB info module\n");

    // Try fib_get_table with error handling
    try_fig_get_table(net);
    
    // Analyze routing table through lookups (doesn't require fib_get_table)
    analyze_routing_table(net);
    
    // Mention netlink option
    netlink_route_query();
    
    // Iterate through all network devices
    rcu_read_lock();
    for_each_netdev_rcu(net, dev) {
        printk(KERN_INFO "\nChecking device %s:\n", dev->name);
        fsleep(1000);
        switch (SELECT)
        {
        case 1:
            get_device_routes(dev);
            break;
        case 2:
            get_device_struct(dev);
            break;
        case 3:
            // Already done above, but we can repeat per device if needed
            analyze_routing_table(net);
            break;
        default:
            printk(KERN_INFO "Using default: checking device routes\n");
            get_device_routes(dev);
            break;
        }
    }
    rcu_read_unlock();
    
    return 0;
}

static void __exit cleanup_fib_info(void)
{
    printk(KERN_INFO "Unloading FIB info module\n");
}


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Alessandro Torrisi");
MODULE_DESCRIPTION("Enhanced FIB Information Display Module");

module_init(fib_info_init);
module_exit(cleanup_fib_info);