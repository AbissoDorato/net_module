# net_module
A linux module to retrive information reguarding the current network state 


## Usage 
- Compile the module using make
- Use the two bash scripts to load the module inside the kernel
 `sudo ./fib_load`
- use dmesg to see the state of the network, output should look like this



## Resources and links 
- https://github.com/torvalds/linux/blob/master/include/net/ip_fib.h
    - contains struct
- https://github.com/torvalds/linux/blob/master/include/net/net_namespace.h
    - contains the net strucure 
- https://github.com/torvalds/linux/blob/master/include/net/nexthop.h
    - structs nexthop
- https://github.com/torvalds/linux/blob/master/include/net/route.h
    - structs for routing tables 

  
### Future implementations 
- net tracker ? (net_namespace.h)