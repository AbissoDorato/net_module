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
#include <linux/types.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <net/ip_fib.h>
#include <net/route.h>
#include <linux/rtnetlink.h>

#define SELECT 2 // 1 for routes, 2 for device struct


static void print_fib_info(struct fib_info *fi);
static int get_device_routes(struct net_device *dev);
static void print_route_info(struct fib_result *res);

const char *scope_to_string(unsigned char scope) {

    // there are more scope, these are scope that are for the user -> maybe see what are just  from the kernel
    switch (scope) {
        case RT_SCOPE_UNIVERSE: return "Universe";
        case RT_SCOPE_SITE: return "Site";
        case RT_SCOPE_LINK: return "Link";
        case RT_SCOPE_HOST: return "Host";
        case RT_SCOPE_NOWHERE: return "Nowhere";
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
        if (res.fi)
            print_fib_info(res.fi);
            print_route_info(&res);
        return 0;
    }else{
        printk(KERN_ERR "No route found for device %s\n", dev->name);
    }

    
    return -ENOENT;
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

static void print_fib_info(struct fib_info *fi)
{
    int i;
    
    if (!fi)
        return;

    printk(KERN_INFO "FIB Info:\n");
    printk(KERN_INFO "  Protocol: %s\n", fib_protocol_to_string(fi->fib_protocol));
    printk(KERN_INFO "  Scope: %u\n", fi->fib_scope);
    printk(KERN_INFO "  Type: %u\n", fi->fib_type);
    printk(KERN_INFO "  Priority: %u\n", fi->fib_priority);
    
    // Print next hop information
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
    // this let you print the MAC address 
    printk(KERN_INFO "Device address: %pM\n", dev->perm_addr);
    get_feature_dev(feat,dev->name);

}



static int __init fib_info_init(void)
{
    struct net_device *dev;
    struct net *net = &init_net;
    
    printk(KERN_INFO "Loading FIB info module\n");
    
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
        
        default:
            break;
        }
        
        
    }
    rcu_read_unlock();
    
    return 0;
}


void cleanup_fib_info(void)
{
	// should i like clean the netdevice? i don't think so? 
    printk(KERN_INFO "Goodbye World.\n");
}


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Alessandro Torrisi");
MODULE_DESCRIPTION("FIB Information Display Module");

module_init(fib_info_init);
module_exit(cleanup_fib_info);