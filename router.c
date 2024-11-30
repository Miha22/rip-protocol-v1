#define EVENT_LOG_DEBUG 0
#define EVENT_LOG_MSG   1
#define EVENT_LOG_WARN  2
#define EVENT_LOG_ERR   3

#include "router.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <linux/if_packet.h>
#include <ifaddrs.h>
#include <poll.h>
#include <pthread.h>
#include <event2/event.h>
#include <event2/event_struct.h>
#include "lib/libpatricia/libpatricia/patricia.h"
#include  "lib/libpatricia/libpatricia/patricia.c"
#include "patricia.h"

void destroy_node(void *data) ;
void print_patricia_tree(patricia_tree_t *tree);

#define MAXBUFLEN 100
#define MAX_ENTRIES 25
#define CHECK_INTERVAL 3
#define MAX_INTERFACES 5

typedef void (*event_callback_fn)(evutil_socket_t, short, void *);
typedef struct {
    patricia_tree_t *tree;
    pthread_rwlock_t lock;
} synchronized_patricia_t;
static synchronized_patricia_t *rtable = NULL; 

struct broadcast_info {
    char ip_str[INET_ADDRSTRLEN];
    char ifname[IFNAMSIZ];
};

struct broadcast_info cached_broadcasts[MAX_INTERFACES];
int num_broadcasts = 0;

struct rip_entry {
    uint16_t family;
    uint16_t route_tag;
    uint32_t ip_addr;
    uint32_t subnet_mask;
    uint32_t next_hop;
    uint32_t metric;
    uint32_t source;
};

struct rip_packet {
	uint8_t cmd;
	uint8_t ver;
	uint16_t pad;
    uint8_t num_entries;
	struct rip_entry *entries[MAX_ENTRIES];
};

void print_afinet(struct in_addr, char* msg) {
    char ip[INET_ADDRSTRLEN]; 
    printf("%s %s\n",
                msg,
                inet_ntop(AF_INET, inet_addr, ip, INET_ADDRSTRLEN)
            );
}

void cache_broadcast_addresses() {
    struct ifaddrs *ifaddr, *ifa;

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        return;
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET) {
            continue;
        }

        struct sockaddr_in *ip_s = (struct sockaddr_in *)ifa->ifa_addr;
        struct sockaddr_in *netmask = (struct sockaddr_in *)ifa->ifa_netmask;

        if (ip_s->sin_addr.s_addr == inet_addr("127.0.0.1")) {
            continue;
        }

        in_addr_t ip_addr = ntohl(ip_s->sin_addr.s_addr);
        in_addr_t netmask_addr = ntohl(netmask->sin_addr.s_addr);
        in_addr_t broadcast = ip_addr | (~netmask_addr);

        struct in_addr broadcast_addr = { htonl(broadcast) };

        if (!inet_ntop(AF_INET, &broadcast_addr, cached_broadcasts[num_broadcasts].ip_str, INET_ADDRSTRLEN)) {
            perror("\tinet_ntop");
            continue;
        }

        strncpy(cached_broadcasts[num_broadcasts].ifname, ifa->ifa_name, IFNAMSIZ);
        num_broadcasts++;
    }

    freeifaddrs(ifaddr);
}

void encode_packet(struct rip_packet *p, char *buffer, size_t *out_len) {
	char *ptr = buffer;
	*ptr++ = p->cmd;
	*ptr++ = p->ver;
	uint16_t pad = htons(p->pad);
	memcpy(ptr, &pad, sizeof (uint16_t));
	ptr += sizeof(uint16_t);
    *ptr++ = p->num_entries;

    if (p->num_entries > MAX_ENTRIES) {
        fprintf(stderr, "Too many entries to encode: %d\n", p->num_entries);
        *out_len = 0;
        return;
    }

	for (uint8_t i = 0; i < p->num_entries; i++)
	{
		struct rip_entry e = *p->entries[i];

		uint16_t family = htons(e.family);
		uint16_t route_tag = htons(e.route_tag);
		uint32_t ip_addr = htonl(e.ip_addr);
		uint32_t subnet_mask = htonl(e.subnet_mask);
		uint32_t next_hop = htonl(e.next_hop);
		uint32_t metric = htonl(e.metric);
        uint32_t source = htonl(e.source);

		memcpy(ptr, &family, sizeof (uint16_t));
		ptr += sizeof(uint16_t);
		memcpy(ptr, &route_tag, sizeof (uint16_t));
		ptr += sizeof(uint16_t);
		memcpy(ptr, &ip_addr, sizeof (uint32_t));
		ptr += sizeof(uint32_t);
		memcpy(ptr, &subnet_mask, sizeof (uint32_t));
		ptr += sizeof(uint32_t);
		memcpy(ptr, &next_hop, sizeof (uint32_t));
		ptr += sizeof(uint32_t);
		memcpy(ptr, &metric, sizeof (uint32_t));
		ptr += sizeof(uint32_t);
        memcpy(ptr, &source, sizeof (uint32_t));
		ptr += sizeof(uint32_t);
	}
	*out_len = ptr - buffer;
} 

void decode_packet(struct rip_packet *packet, char *buffer) {
	char *ptr = buffer;

    packet->cmd = *ptr++;
    packet->ver = *ptr++;

    uint16_t pad;
    memcpy(&pad, ptr, sizeof(uint16_t));
    packet->pad = ntohs(pad);
    ptr += sizeof(uint16_t);

    packet->num_entries = *ptr++;
    if (packet->num_entries > MAX_ENTRIES) {
        fprintf(stderr, "Too many entries in packet: %d\n", packet->num_entries);
        packet->num_entries = 0;
        return;
    }

    for (int i = 0; i < packet->num_entries; i++) {
        packet->entries[i] = malloc(sizeof(struct rip_entry));
        if (!packet->entries[i]) {
            perror("malloc in decode packet");

            for (int j = 0; j < i; j++) {
                free(packet->entries[j]);
            }
            packet->num_entries = 0;
            return;
        }

        struct rip_entry *entry = packet->entries[i];

        uint16_t family, route_tag;
        uint32_t ip_addr, subnet_mask, next_hop, metric, source;

        memcpy(&family, ptr, sizeof(uint16_t));
        entry->family = ntohs(family);
        ptr += sizeof(uint16_t);

        memcpy(&route_tag, ptr, sizeof(uint16_t));
        entry->route_tag = ntohs(route_tag);
        ptr += sizeof(uint16_t);

        memcpy(&ip_addr, ptr, sizeof(uint32_t));
        ip_addr = ntohl(ip_addr);
        memcpy(&entry->ip_addr, &ip_addr, sizeof(uint32_t));
        ptr += sizeof(uint32_t);

        memcpy(&subnet_mask, ptr, sizeof(uint32_t));
        subnet_mask = ntohl(subnet_mask);
        memcpy(&entry->subnet_mask , &subnet_mask, sizeof(uint32_t));
        ptr += sizeof(uint32_t);

        memcpy(&next_hop, ptr, sizeof(uint32_t));
        next_hop = ntohl(next_hop);
        memcpy(&entry->next_hop , &next_hop, sizeof(uint32_t));
        ptr += sizeof(uint32_t);

        memcpy(&metric, ptr, sizeof(uint32_t));
        entry->metric = ntohl(metric);
        ptr += sizeof(uint32_t);

        memcpy(&source, ptr, sizeof(uint32_t));
        source = ntohl(source);
        memcpy(&entry->source, &source, sizeof(uint32_t));
        entry->source = ntohl(source);
        ptr += sizeof(uint32_t);
    }
}
int calculate_bitlen(uint32_t netmask) {
    int bitlen = 0;
    while (netmask) {
        bitlen += netmask & 1;
        netmask >>= 1;
    }
    return bitlen;
}
void add_ip_to_patricia_tree(patricia_tree_t *tree, uint32_t ip_network_order, uint32_t mask_network_order) {
    struct in_addr addr;
    memcpy(&addr, &ip_network_order, sizeof(addr));

    uint32_t mask_host_order = ntohl(mask_network_order);
    int bitlen = calculate_bitlen(mask_host_order);
    if (bitlen > 32) {
        fprintf(stderr, "Invalid subnet mask\n");
        return;
    }

    prefix_t *prefix = New_Prefix(AF_INET, &addr, bitlen);
    if (!prefix) {
        fprintf(stderr, "Failed to create prefix\n");
        return;
    }

    patricia_node_t *node = patricia_lookup(tree, prefix);
    if (!node) {
        fprintf(stderr, "Failed to insert prefix into Patricia tree\n");
        Deref_Prefix(prefix);
        return;
    }

    Deref_Prefix(prefix);

    printf("Inserted prefix: %s/%d\n", inet_ntoa(addr), bitlen);
}
void read_callback(evutil_socket_t sockfd, short events, void *arg) {
    char buffer[512];
    struct sockaddr_in src_addr;
    struct iovec iov[1];
    struct msghdr msg;
    char cmsgbuf[CMSG_SPACE(sizeof(struct in_pktinfo))];
    struct in_pktinfo *pktinfo = NULL;

    iov[0].iov_base = buffer;
    iov[0].iov_len = sizeof(buffer) - 1;

    memset(&msg, 0, sizeof(msg));
    msg.msg_name = &src_addr;
    msg.msg_namelen = sizeof(src_addr);
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsgbuf;
    msg.msg_controllen = sizeof(cmsgbuf);

    int len = recvmsg(sockfd, &msg, 0);
    if (len <= 0) {
        perror("recvmsg error");
        return;
    }
    buffer[len] = '\0';

    for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
        if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_PKTINFO) {
            pktinfo = (struct in_pktinfo *)CMSG_DATA(cmsg);
            break;
        }
    }

    if (!pktinfo) {
        fprintf(stderr, "Failed to retrieve receiving interface information\n");
        return;
    }

    char ifname[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &pktinfo->ipi_addr, ifname, INET_ADDRSTRLEN);

    struct rip_packet *packet_ptr = malloc(sizeof(struct rip_packet));
    if (!packet_ptr) {
        fprintf(stderr, "Memory allocation failed for RIP packet\n");
        return;
    }

    decode_packet(packet_ptr, buffer);


    if (packet_ptr->num_entries > MAX_ENTRIES) {
        fprintf(stderr, "Received packet has too many entries: %d\n", packet_ptr->num_entries);
        free(packet_ptr);
        return;
    }


    if (pktinfo->ipi_addr.s_addr == src_addr.sin_addr.s_addr) {
        printf("Ignoring packet broadcasted by this host\n");
        free(packet_ptr);
        return;
    }

    struct ifaddrs *ifaddr, *ifa;
    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        return;
    }

    for (uint8_t i = 0; i < packet_ptr->num_entries; i++) {
        struct rip_entry *r_entry = packet_ptr->entries[i];
        //because of broadcast nature -> need to iterate over interfaces
        uint8_t split_horizon = 0;
        for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
            if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET) {
                continue;
            }

           uint32_t local_addr = ntohl(((struct sockaddr_in *)ifa->ifa_addr)->sin_addr.s_addr);

            if (local_addr == r_entry->source) {
                printf("Ignoring route due to split horizon: source=%s, for network(entry)=%s\n",
                    inet_ntoa(*(struct in_addr *)&r_entry->source),
                    inet_ntoa(*(struct in_addr *)&r_entry->ip_addr)
                );

                split_horizon = 1;
                break;
            }
        }
        
        if (split_horizon) continue;

        uint32_t source = r_entry->source;
        uint16_t family = r_entry->family;
        uint32_t net_addr_nl = htonl(r_entry->ip_addr);
        uint32_t mask_nl= htonl(r_entry->subnet_mask);
        uint32_t next_hop = r_entry->next_hop;
        uint32_t metric = r_entry->metric;

        struct in_addr *addr_ptr = malloc(sizeof (struct in_addr));
        addr_ptr->s_addr = net_addr_nl;

        printf("Processing entry network: %s\n", inet_ntoa(*(struct in_addr *)&r_entry->ip_addr));
        char ip_src[INET_ADDRSTRLEN]; 
        char ip[INET_ADDRSTRLEN]; 
        uint16_t bitlen = 0;

        for(char i = 31; i > -1 && r_entry->subnet_mask & (1 << i); i--) {
            bitlen++;
        }
        if(metric + 1 > 15) {
            printf("Discarding long range entry for net: %s/%d from %s",
                inet_ntop(r_entry->family, addr_ptr, ip, INET_ADDRSTRLEN), 
                bitlen,
                inet_ntop(src_addr.sin_family, &src_addr.sin_addr.s_addr, ip_src, INET_ADDRSTRLEN)
            );
            continue;
        }

        prefix_t *prefix = New_Prefix(AF_INET, addr_ptr, bitlen);
        if (!prefix) {
            fprintf(stderr, "\tFailed to create prefix\n");
            return;
        }
        patricia_node_t *search_result = patricia_search_exact(rtable->tree, prefix);

        if(search_result) {
            struct rip_entry *pat_r_entry = (struct rip_entry *)search_result->data;
            printf("\tFound entry: %s for prefix %s (data address: %p)\n", 
                inet_ntoa(*(struct in_addr *)&prefix->add.sin.s_addr), 
                inet_ntoa(*(struct in_addr *)&r_entry->ip_addr),
                (void *)pat_r_entry
            );

            if(metric + 1 < pat_r_entry->metric) {
                pat_r_entry->next_hop = ntohl(src_addr.sin_addr.s_addr);
                pat_r_entry->metric = metric + 1;
                pat_r_entry->source = source;
            }
        }
        else {
            patricia_node_t *node = patricia_lookup(rtable->tree, prefix);
            if(!node) {
                fprintf(stderr, "\tFailed to add node to Patricia tree\n");
            }
            else {
                printf("\tInserting prefix: %s/%d (address: %p)\n", 
                inet_ntoa(prefix->add.sin), prefix->bitlen, (void *)prefix);

                if(metric == 0) {
                    r_entry->source = ntohl(src_addr.sin_addr.s_addr);
                }
                else {
                    printf("\tpropagated entry for %s\n", inet_ntoa(*(struct in_addr *)&r_entry->ip_addr));
                }
                r_entry->next_hop = ntohl(src_addr.sin_addr.s_addr);
                r_entry->metric = metric + 1;
                node->data = malloc(sizeof(struct rip_entry));
                memcpy(node->data, r_entry, sizeof(struct rip_entry));
            }
        }
        Deref_Prefix(prefix);
    }
    freeifaddrs(ifaddr);
    print_patricia_tree(rtable->tree);
    for (uint8_t i = 0; i < packet_ptr->num_entries; i++) {
        free(packet_ptr->entries[i]);
    }
    free(packet_ptr);
}

int send_packet(int sockfd, const char *ip, const char *port, const char *message, size_t msg_len) {
    struct addrinfo hints, *servinfo, *p;
    int rv;
    int sent = 0;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET; 
    hints.ai_socktype = SOCK_DGRAM; 

    if ((rv = getaddrinfo(ip, port, &hints, &servinfo)) != 0) {
        //fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return -1;
    }

    for (p = servinfo; p != NULL; p = p->ai_next) {
        if (sendto(sockfd, message, msg_len, 0, p->ai_addr, p->ai_addrlen) == -1) {
            perror("sendto");
            continue;
        }

        char dest_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &((struct sockaddr_in *)p->ai_addr)->sin_addr, dest_ip, sizeof(dest_ip));
        //printf("Sent %zu bytes to %s:%s (%s)\n", msg_len, ip, port, dest_ip);
        sent = 1;
        break; 
    }

    if (!sent) {
        fprintf(stderr, "Failed to send packet to %s:%s\n", ip, port);
    }

    freeaddrinfo(servinfo);
    return sent ? 0 : -1;
}

void write_callback(evutil_socket_t fd, short events, void *arg) {
    char buf[512];
    size_t len = 0;

    static patricia_node_t *last_node = NULL;
    struct rip_packet *packet_ptr = malloc(sizeof (struct rip_packet));
    if (packet_ptr == NULL) {
        perror("\tmalloc");
        free(packet_ptr);
        return;
    }

    packet_ptr->cmd = 2;
    packet_ptr->ver = 2;
    packet_ptr->pad = 0;

    patricia_node_t *node = rtable->tree->head; 
    uint8_t counter = 0;
    uint8_t found_last_node = (last_node == NULL);
    PATRICIA_WALK(node, node) {
        if (!found_last_node) {
            if (node == last_node) {
                found_last_node = 1; 
            }
            continue; 
        }
        if (node->data) {
            if (counter >= MAX_ENTRIES) {
                last_node = node;
                break;
            }
            struct rip_entry *e = (struct rip_entry *)node->data;
            packet_ptr->entries[counter++] = e;
        }
    } PATRICIA_WALK_END;

    if (!node) {
        last_node = NULL;
    }

    packet_ptr->num_entries = counter;
    encode_packet(packet_ptr, buf, &len);

    for (int i = 0; i < num_broadcasts; i++) {
        send_packet(fd, cached_broadcasts[i].ip_str, "1520", buf, len);
        usleep(100000);//100ms
    }
    free(packet_ptr);
}

void *get_in_addr(struct sockaddr *saddr) {
	if (saddr->sa_family == AF_INET) {
		return &(((struct sockaddr_in *)saddr)->sin_addr);
	}
	return &(((struct sockaddr_in6 *)saddr)->sin6_addr);
}

int rip_msocket(uint16_t family, uint16_t flags, const char *ip, const char *port, const char *interface) {
    int fd, rv;
    struct addrinfo hints, *ai, *p;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = family;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = flags;

    if (!ip) {
        if (family == AF_INET) {
            ip = "0.0.0.0";
        } else if (family == AF_INET6) {
            ip = "::";
        }
    }

    if ((rv = getaddrinfo(ip, port, &hints, &ai)) != 0) {
        fprintf(stderr, "Error getting addrinfo: %s\n", gai_strerror(rv));
        return -1;
    }

    for (p = ai; p != NULL; p = p->ai_next) {
        fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (fd < 0) {
            perror("socket");
            continue;
        }

        int on = 1;
        if (setsockopt(fd, IPPROTO_IP, IP_PKTINFO, &on, sizeof(on)) < 0) {
            perror("setsockopt(IP_PKTINFO)");
            continue;
        }

        if (setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &on, sizeof(on)) < 0) {
            perror("setsockopt SO_BROADCAST");
            close(fd);
            continue;
        }

        if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
            perror("setsockopt SO_REUSEADDR");
            close(fd);
            continue;
        }

        if (bind(fd, p->ai_addr, p->ai_addrlen) < 0) {
            perror("bind");
            close(fd);
            continue;
        }

        // multicast that failed due to mininet
        // struct ip_mreq mreq;
        // inet_pton(AF_INET, "224.0.0.9", &mreq.imr_multiaddr);

        // if (interface) {
        //     if (inet_pton(AF_INET, interface, &mreq.imr_interface.s_addr) != 1) {
        //         fprintf(stderr, "Invalid interface IP: %s\n", interface);
        //         close(fd);
        //         return -1;
        //     }
        // } else {
        //     mreq.imr_interface.s_addr = htonl(INADDR_ANY);
        // }

        // if (setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
        //     perror("setsockopt: IP_ADD_MEMBERSHIP");
        //     close(fd);
        //     continue;
        // }

        // int ttl = 5; 
        // if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl)) < 0) {
        //     perror("setsockopt IP_MULTICAST_TTL");
        // }
        break; 
    }

    if (p == NULL) {
        fprintf(stderr, "listener: failed to bind socket\n");
        freeaddrinfo(ai);
        return -1;
    }


    freeaddrinfo(ai);
    return fd;
}

void str2nl(const char *ip_with_prefix, struct in_addr *ip, int *prefix_length) {
    char ip_copy[INET_ADDRSTRLEN + 3]; //192.168.0.1/24 + '\0'"
    strncpy(ip_copy, ip_with_prefix, sizeof(ip_copy) - 1);
    ip_copy[sizeof(ip_copy) - 1] = '\0';

    char *ip_str = strtok(ip_copy, "/");
    char *prefix_str = strtok(NULL, "/");

    if (ip_str && prefix_str) {
        if (inet_pton(AF_INET, ip_str, ip) != 1) {
            fprintf(stderr, "Invalid IP address: %s\n", ip_str);
            exit(EXIT_FAILURE);
        }
        *prefix_length = atoi(prefix_str);
    } else {
        fprintf(stderr, "Invalid IP/prefix format: %s\n", ip_with_prefix);
        exit(EXIT_FAILURE);
    }
}

void print_prefix(prefix_t *prefix) {
    if (!prefix) return;

    char ip_str[INET_ADDRSTRLEN];
    if (prefix->family == AF_INET) {
        inet_ntop(AF_INET, &(prefix->add.sin), ip_str, INET_ADDRSTRLEN);
        printf("%s/%d\n", ip_str, prefix->bitlen);
    }
}

void print_patricia_tree(patricia_tree_t *tree) {
    patricia_node_t *node;

    printf("Patricia Tree Contents\n");
    PATRICIA_WALK(tree->head, node) {
        printf("Node: ");
        print_prefix(node->prefix);

        if (node->data) {
            struct rip_entry *e = (struct rip_entry *)node->data;
            printf(" Metric: %u, Next Hop: %s\n",
                e->metric,
                inet_ntoa(*(struct in_addr *)&e->next_hop)
            );
        }
    } PATRICIA_WALK_END;
}
void destroy_node(void *data) {
    if(data) {
        free(data);
    }
}
void destory_patricia() {
    pthread_rwlock_destroy(&rtable->lock);
    Destroy_Patricia(rtable->tree, destroy_node);
    free(rtable);
}
uint32_t init_rtable(patricia_tree_t *rtable_tree) {
     struct ifaddrs *ifaddr, *ifa;

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        return -1;
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET) continue;

        struct sockaddr_in *ip_s = (struct sockaddr_in *)ifa->ifa_addr;//gives  little endian
        struct sockaddr_in *netmask = (struct sockaddr_in *)ifa->ifa_netmask;//gives  little endian

        if (ip_s->sin_addr.s_addr == htonl(INADDR_LOOPBACK)) continue;

        if (!netmask) {
            fprintf(stderr, "No netmask available for interface: %s\n", ifa->ifa_name);
            continue;
        }

        uint32_t ip_addr_nl = ip_s->sin_addr.s_addr;
        uint32_t mask_nl = netmask->sin_addr.s_addr;
        uint32_t mask_hl = ntohl(mask_nl);

        uint16_t bitlen = 0;
        for (int i = 31; i >= 0 && (mask_hl & (1 << i)); i--) {
            bitlen++;
        }

        if (bitlen > 32) {
            fprintf(stderr, "Invalid subnet mask\n");
            freeifaddrs(ifaddr);
            return EXIT_FAILURE;
        }

        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ip_s->sin_addr), ip_str, INET_ADDRSTRLEN);
        printf("Interface: %s\n", ifa->ifa_name);
        printf("IP Address (String): %s/%d\n", ip_str, bitlen);

        // prefix_t *prefix = malloc(sizeof(prefix_t));
        // if (!prefix) {
        //     fprintf(stderr, "Failed to create prefix\n");
        //     Destroy_Patricia(rtable, NULL);
        //     freeifaddrs(ifaddr);
        //     return EXIT_FAILURE;
        // }
        // prefix->family = AF_INET;
        // prefix->bitlen = bitlen;
        // prefix->add.sin.s_addr = ip_addr_nl & mask_nl;
        //struct in_addr addr = { .s_addr = htonl(ntohl(ip_addr_nl) & ntohl(mask_nl))};
        struct in_addr *addr_ptr = malloc(sizeof (struct in_addr));
        addr_ptr->s_addr = ip_addr_nl & mask_nl;
        prefix_t *prefix = New_Prefix(AF_INET, addr_ptr, bitlen);
        if (!prefix) {
            fprintf(stderr, "\tFailed to create prefix\n");
            return EXIT_FAILURE;
        }

        struct rip_entry *r_entry = malloc(sizeof(struct rip_entry));
        if (!r_entry) {
            fprintf(stderr, "Failed to create RIP entry\n");
            destory_patricia();
            freeifaddrs(ifaddr);
            return EXIT_FAILURE;
        }

        r_entry->family = AF_INET;
        r_entry->ip_addr = ntohl(ip_addr_nl) & ntohl(mask_nl); 
        r_entry->subnet_mask = ntohl(mask_nl); 
        r_entry->metric = 0;
        r_entry->route_tag = 0;
        r_entry->next_hop = 0;
        r_entry->source = 0;

        patricia_node_t *node = patricia_lookup(rtable_tree, prefix);
        if (!node) {
            fprintf(stderr, "Failed to add node to Patricia tree\n");
            free(r_entry);
            destory_patricia();
            freeifaddrs(ifaddr);
            return EXIT_FAILURE;
        } else {
            node->data = r_entry;
        }
    }
    freeifaddrs(ifaddr);
    return 0;
}

int main(int argc, char *argv[]) {
    rtable = malloc(sizeof(synchronized_patricia_t));
    if(!rtable) {
        perror("Failed to allocate memory for rtable");
        return EXIT_FAILURE;
    }
    rtable->tree = New_Patricia(32);
    if (!rtable->tree) {
        perror("Failed to create Patricia tree");
        free(rtable);
        return EXIT_FAILURE;
    }

    if (pthread_rwlock_init(&rtable->lock, NULL) != 0) {
        perror("Failed to initialize rwlock");
        Destroy_Patricia(rtable->tree, destroy_node); // Cleanup the Patricia tree
        free(rtable);
        return EXIT_FAILURE;
    }
    init_rtable(rtable->tree);
    cache_broadcast_addresses();

    char* self_port = NULL;
    int id = 1;
    if (argc == 2) {
        id = atoi(argv[1]); 
        if (id < 0 || id > 255) {
            fprintf(stderr, "Invalid router ID. Please provide a number between 0 and 255.\n");
            return 1;
        }
        self_port = "1520";
    }

    if (argc == 3) {
        self_port = argv[2];
        id = atoi(argv[1]); 
        if (id < 0 || id > 255) {
            fprintf(stderr, "Invalid router ID. Please provide a number between 0 and 255.\n");
            return 1;
        }
    } else {
        printf("Usage: %s <self_port>\nUsing default port: 1520\n", argv[0]);
        printf("Invalid router ID. Please provide a number between 0 and 255.\n");
        self_port = "1520";
    }
    
    struct event_base *ebase = event_base_new();
    if (!ebase) {
        fprintf(stderr, "Failed to create event base\n");
        return 1;
    }
    
    int sockfd = rip_msocket(AF_INET, AI_PASSIVE, NULL, self_port, NULL);
    if (sockfd == -1) {
        fprintf(stderr, "Failed to create socket\n");
        event_base_free(ebase);
        destory_patricia();
        return EXIT_FAILURE;
    }

    struct event *read_event = event_new(ebase, sockfd, EV_READ | EV_PERSIST, read_callback, NULL);
    if (!read_event || event_add(read_event, NULL) == -1) {
        fprintf(stderr, "Failed to set up read event\n");
        close(sockfd);
        event_base_free(ebase);
        destory_patricia();
        return EXIT_FAILURE;
    }

    srand(time(NULL));
    //struct timeval timer_interval = { 5 + (rand() % 3), 0 };
    int initial_delay = id * 100; // Unique delay based on router ID
    struct timeval timer_interval = {5 * 2, initial_delay * 1000};
    struct event *periodic_event = event_new(ebase, sockfd, EV_PERSIST, write_callback, NULL);
    if (!periodic_event || event_add(periodic_event, &timer_interval) == -1) {
        fprintf(stderr, "Failed to set up periodic write event\n");
        event_free(read_event);
        close(sockfd);
        event_base_free(ebase);
        destory_patricia();
        return EXIT_FAILURE;
    }

    if (event_base_dispatch(ebase) == -1) {
        fprintf(stderr, "Event base dispatch failed\n");
        event_free(read_event);
        event_free(periodic_event);
        close(sockfd);
        event_base_free(ebase);
        destory_patricia();
        return EXIT_FAILURE;
    }
    
    event_free(read_event);
    event_free(periodic_event);
    close(sockfd);
    event_base_free(ebase);
    destory_patricia();

    return EXIT_SUCCESS;
}