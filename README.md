## Routing Information Protocol Version 1
### Overview
A routing information sharing protocol based on sockets according to RFC 2453 https://datatracker.ietf.org/doc/html/rfc2453 documentation. The project is launched on a single physical host creating virtual interfaces/network topology in **mininet**. There are two direct dependencies: *libevent*, *cc-common*. And *mininet* (of course). 
> *// Pox and pox modules learning, hub etc. were ommited.*
#### libevent 
Provides event loop for generating periodic routing updates and permanent non-blocking socket listening. Compiled statically.

#### cc-common
A collection of helper C code. The project uses Patricia trie implementation for storing routing table in radix tree style. The patricia tree was already adapted to network research projects.

### Implemented features of RIP Version 2 (RIPv2)

- Distance-Vector Algorithm: 
    - [x] Periodic broadcasting of the routing table (Bellman-Ford algorithm).

- Classless Inter-Domain Routing (CIDR):
    - [x] Includes support for subnet masks in routing updates.
    - [x] Facilitates Variable Length Subnet Masking (VLSM).

- Multicast Communication:
    - [ ] Routing updates are sent via multicast address (224.0.0.9) instead of broadcast, reducing unnecessary load on non-RIP devices.
> The error setsockopt: IP_ADD_MEMBERSHIP: *No such device*. Multicast traffic may not be enabled or routed correctly in the Mininet topology. // In progress..

- Metric:
    - [x] Same hop count metric as RIPv1, with a maximum of 15.

- Periodic Updates:
    - [x] Updates sent every 30 seconds, as in RIPv1.

- Split Horizon with Poison Reverse:
    - [x] Enhances split horizon by advertising routes learned on an interface with a metric of 16 (infinity) back to the same interface.
> // Was implemented on receiver side since writer broadcasts.  

- Authentication:
    - [ ] Supports authentication of routing updates.
        Can use plain-text passwords or MD5 authentication for improved security.

- Scalability Improvements:
    - [ ] Supports larger and more flexible networks due to subnetting and CIDR.
> // have not tested on large networks, since there exist things like BGP and OSPF.

- Next-Hop Specification:
    - [x] Includes the next-hop address in routing updates, enabling more efficient routing decisions.

- Backward Compatibility:
    - [x] RIPv2 is backward-compatible with RIPv1, allowing mixed environments during migration.

### Test Topology
For a sake of testing I subnetted the 192.168.0.0/24 network into 4 subnets **{i}** by borrowing 2 host bits to test masking. The subnets are: the main router **r0** was sitting on every **((x.x.0.1 + 64 * i))** and each intermediary router **ri{j}** on **((x.x.0.1 + j + 64 * i))** address and **/26** masks. Deducing network and broadcast addresses were straightforward by either resetting or setting host part with mask of corresponding address. Simple topology is given below, the main router merges the 3 subnets. 

0. **r0 Main router** - 3 interfaces
    1. **ri0 Intermediary router** - 2 interfaces
        1. **s0 Switch** - 2 interfaces
            1. **h0 Host *10.0.0.100/24*** - 1 interface
    2. **ri1 Intermediary router**
        1. **s1 Switch**
            1. **h1 Host *11.0.0.100/24***
    3. **ri2 Intermediary router**
        1. **s2 Switch**
            1. **h2 Host *12.0.0.100/24***

## Implementation and details
- The code is compiled as binary having dynamic dependency on libevent (many .so) and static dependency on patricia tree. The binary is launched by each router in isolated environment provided by mininet, so there is no single port conflict thankfully. The port used in code is **1520** since routers do not have sudo access to local machine as they launch binary as
```
router_x.cmd(path_to_binary)
```
> // The mininet does not hand over sudo access to sub processes.

## Outcomes

After some time, all routers synchronized routing tables and were able to determine which interface to use to hand over packet. 

#### Routing table at Main router R0
| Network  | Next hop | Metric |
| ------------- |:-------------:|:-------------|
| 192.168.0.0/26      | 0     |  0  |
| 192.168.0.64/26      | 0     | 0     |
| 192.168.0.128/26      | 0     | 0     |
| 12.0.0.0/24      | 192.168.0.2     | 1     |
| 11.0.0.0/24      | 192.168.0.66     | 1     |
| 10.0.0.0/24     | 192.168.0.130     | 1     |

**metric = 0** it means network is directly connected. The table initialization gathers all directly connected networks and sets zeros for metric and next hop. 

## Observations and Prerequisites

Make sure to compile **cc-common** first, as it has own compilation process without cmake. It has older option with *automake* and *./configure* for generating Makefiles. I have added the CMakeLists.txt to the cc-common source directory to create dependency by including its MakeFiles *(for patricia tree only (since cc-common is a collection of tools))* with global project's cmake build process. The cc-common was then added as subdirectory and cmake successfully compiled the target as static library. Additionally, I wanted libevent be compiled statically to make the whole code portable, but it had too many implicit dynamic dependencies which was too much extra work to compile that cascade of libraries. Finally, I realized that mininet still ables to resolve dynamic linking and successuflly launched binary for each router.

## Launching
1. build cc-common/patricia with automake and ./configure to generate make files as stated in its README.
2. create **build** directory and as always **cmake ..**
3. **make** the binary **RouterEx** shall be created

## Common issue with cc-common
Most likely you wont be able to compile cc-common at first, because its README does not explain the whole process how to build & compile it. I have raised the issue in their repo. They need to add CMakeLists.txt to make their repo compatible as submodule to make compilation automatic, but right now it is expected to do everything manually (build & compile cc-common manually). I did not include the CMakeLists.txt for cc-common because it is a submodule under this project's **lib/** directory *(submodule directory)* and it is not the best practise to push the source code of existing git repo and at the same time forking the whole project just becuase of absence of CMakeLists.txt 

## Further research

There are many ways to progress from here, play with topology size and see how long patricia tree searches exact matches with O(LogN) among hundreds of entries, but that is the limitation of RIP protocol. It is great for small local networks, but for the big topologies there exist BGP the border router protocol for connecting larger networks rather than gossiping protocol. 
