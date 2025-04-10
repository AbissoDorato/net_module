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
#include <net/fib_rules.h> 
#include <linux/netfilter.h>
#include <linux/ip.h>
#include <net/ip_fib.h>


#define SELECT 2 // 1 for routes, 2 for device struct, 3 for the routing tables 


static void print_fib_info(struct fib_info *fi);
static int get_device_routes(struct net_device *dev);
static void print_route_info(struct fib_result *res);

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

// we are not able to get the routing table from the kernel, the only thing that we can do is to do a look up
// if i insert this address, is it in the routing table? and from that we can get infos
static void analyze_routing_table(struct net *net) {
    struct flowi4 fl4;
    struct fib_result res;
    __be32 daddr;
    int i;
    
    printk(KERN_INFO "Analyzing routing tables...\n");

    // Initialize flow structure
    memset(&fl4, 0, sizeof(fl4));
    fl4.flowi4_scope = RT_SCOPE_UNIVERSE;

    // Try different destination addresses to find routes
    for (i = 1; i <= 255; i++) {
        daddr = htonl(0x0A000000 | i);  // 10.0.0.x addresses
        fl4.daddr = daddr;
        
        if (fib_lookup(net, &fl4, &res, 0) == 0) {
            if (res.fi) {
                printk(KERN_INFO "\nRoute found for %pI4:\n", &daddr);
                // Only access fields that are definitely available
                printk(KERN_INFO "  Type: %u\n", res.type);
                printk(KERN_INFO "  Scope: %s\n", 
                       scope_to_string(res.scope));
                
                if (res.nhc) {
                    printk(KERN_INFO "  Next Hop Info:\n");
                    if (res.nhc->nhc_dev) {
                        printk(KERN_INFO "    Device: %s\n", 
                               res.nhc->nhc_dev->name);
                    }
                    printk(KERN_INFO "    Gateway: %pI4\n", 
                           &res.nhc->nhc_gw.ipv4);
                }
            }
        }
    }

    printk(KERN_INFO "\nRouting Table Analysis Complete\n");
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

// Add this function after get_device_struct
static int change_mac_address(struct net_device *dev, unsigned char *new_mac) {
    if (!dev || !new_mac)
        return -EINVAL;

    // Check if device is up
    if (dev->flags & IFF_UP) {
        printk(KERN_ERR "Device must be down to change MAC address\n");
        return -EBUSY;
    }

    // Store old MAC for logging
    printk(KERN_INFO "Old MAC address: %pM\n", dev->dev_addr);
    
    // Copy new MAC address
    if (is_valid_ether_addr(new_mac)) {
        memcpy(dev->dev_addr, new_mac, ETH_ALEN);
        printk(KERN_INFO "New MAC address: %pM\n", dev->dev_addr);
        return 0;
    }

    printk(KERN_ERR "Invalid MAC address provided\n");
    return -EINVAL;
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


static int __init fib_info_init(void)
{
    struct net_device *dev;
    struct net *net = &init_net;
    
    printk(KERN_INFO "Loading FIB info module\n");

    // first we analyze the routing table
    rcu_read_lock();
    analyze_routing_table(net);
    rcu_read_unlock();
 
    
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
            // Print routing table information
            analyze_routing_table(net);
            break;
        default:
        case 4:
            //analyze_routing_table2(net);
            break;

            break;
        }
        
        
    }
    rcu_read_unlock();
    
    return 0;
}


void cleanup_fib_info(void)
{
	// should i like clean the netdevice? i don't think so? 
    printk(KERN_INFO "Aurevoir Shoshana.\n");
}


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Alessandro Torrisi");
MODULE_DESCRIPTION("FIB Information Display Module");

module_init(fib_info_init);
module_exit(cleanup_fib_info);