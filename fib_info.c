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

#define SELECT 1 // 1 for routes, 2 for device struct


static void print_fib_info(struct fib_info *fi);
static int get_device_routes(struct net_device *dev);
static void print_route_info(struct fib_result *res);


void print_route_info(struct fib_result *res) {
    if (!res)
        return;

    printk(KERN_INFO "Route Information:\n");
    printk(KERN_INFO "  Prefix: %pI4/%u\n", &res->prefix, res->prefixlen);
    printk(KERN_INFO "  Type: %u\n", res->type);
    printk(KERN_INFO "  Scope: %u\n", res->scope);

    if (res->nhc) {
        printk(KERN_INFO "  Next Hop:\n");
        printk(KERN_INFO "    Device: %s\n", res->nhc->nhc_dev ? 
               res->nhc->nhc_dev->name : "none");
        printk(KERN_INFO "    Gateway: %pI4\n", &res->nhc->nhc_gw.ipv4);
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
    default: printk(KERN_INFO "Unknown protocol: %d\n", proto);
        return "Unknown";
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

static void get_feature_dev(netdev_features_t *feat, char *name){
    // this let you print the MAC address 
    printk(KERN_INFO "Device features of %s\n", name);
    // here is possible to add more flags that are present in netdev_features.h --> those are just some of them 
    if (*feat & NETIF_F_SG)
        printk(KERN_INFO "NETIF_F_SG is set\n");
    else
        printk(KERN_INFO "NETIF_F_SG is not set\n");
    
    if (*feat & NETIF_F_IP_CSUM)
        printk(KERN_INFO "NETIF_F_IP_CSUM is set\n");
    else
        printk(KERN_INFO "NETIF_F_IP_CSUM is not set\n");
    
    if (*feat & NETIF_F_IPV6_CSUM)
        printk(KERN_INFO "NETIF_F_IPV6_CSUM is set\n");
    else
        printk(KERN_INFO "NETIF_F_IPV6_CSUM is not set\n"); 
}

static void get_feature_dev_hw(netdev_features_t *feat_hw, char *name){
    // this let you print the MAC address 
    printk(KERN_INFO "Device hw features of %s\n", name);
    // here is possible to add more flags that are present in netdev_features.h --> those are just some of them 
    if (*feat_hw & NETIF_F_HW_CSUM)
        printk(KERN_INFO "NETIF_F_HW_CSUM is set\n");
    else
        printk(KERN_INFO "NETIF_F_HW_CSUM is not set\n");
    
    if (*feat_hw & NETIF_F_HW_VLAN_CTAG_TX)
        printk(KERN_INFO "NETIF_F_HW_VLAN_CTAG_TX is set\n");
    else
        printk(KERN_INFO "NETIF_F_HW_VLAN_CTAG_TX is not set\n");
    
}

/*
* Things to check in the device structure:
*- mac address
*- features
*- hw features
*- possible net operations 
*- MPLS feature TBD
*/

static void get_device_struct(struct net_device *dev){

    netdev_features_t *feat = &dev->features;
    netdev_features_t *feat_hw = &dev->hw_features;
    // this let you print the MAC address 
    printk(KERN_INFO "Device address: %pM\n", dev->perm_addr);
    printk(KERN_INFO "Device dev port: %d\n", dev->dev_port);
    // device feature
    get_feature_dev(feat,dev->name);
    get_feature_dev_hw(feat_hw,dev->name);
    // get_feature_dev_mpls

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
            /* info about the route */
            get_device_routes(dev);
            break;
        case 2:
            /* info about the device struct */
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
MODULE_AUTHOR("ALessandro Torrisi");
MODULE_DESCRIPTION("FIB Information Display Module");

module_init(fib_info_init);
module_exit(cleanup_fib_info); 