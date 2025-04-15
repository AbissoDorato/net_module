# net_module
A linux module to retrive information reguarding the current network state 


## Usage 
- Compile the module using make
- run the script fib_full to load,unload and print the log using dmesg



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
- add new metrics
  - operetional state
  - Software integrity
  - BGP Flowspec

