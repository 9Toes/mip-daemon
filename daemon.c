#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <ifaddrs.h>

#define MAX_EVENTS 10
#define MAX_SIZE 1496
#define DEBUG

#define SERVER_FD "/tmp/server_fd_"
#define CLIENT_FD "/tmp/client_fd_"
#define TRANSPORT_FD "/tmp/transport_fd_"

/* Struct for different interfaces */
struct arp_entry {
    uint8_t mip_addr;
    uint8_t mac_addr[6];
    int raw_sock;
};

/* Struct for keeping tabs on sockets and interfaces */
struct daemon {
    int epollfd;
    int client_sock;
    int server_sock;
    int transport_sock;

    int conn_sock_client;
    int conn_sock_server;
    int conn_sock_transport;

    uint8_t destination_mip;
    uint8_t last_received;

    char pending_msg[1496];
    ssize_t frag_size;
    
    /* Interfaces for this daemon */
    struct arp_entry interfaces[256];
    /* Cache for other daemons */
    struct arp_entry arp_cache[256];
};

struct ethernet_frame {
    /* Mac Header */
    uint8_t src_mac[6];
    uint8_t dst_mac[6];
    uint16_t ethernet_type;
    /* Data */
    char data[];
} __attribute__((packed));

struct mip_header {
    uint8_t t : 1; /* Transport: 100 */
    uint8_t r : 1; /* Routing: 010 */
    uint8_t a : 1; /* ARP Broadcast: 001 */
    uint8_t ttl : 4; /* TTL */
    unsigned int length : 9; /* Husk htons */
    uint8_t mip_src; 
    uint8_t mip_dst;
    char payload[];
} __attribute__((packed));


/* 
 * Print MAC-Address 
 * @mac_addr    Array containing the whole mac adress to be printed
 */
#ifdef DEBUG
static void print_mac_addr(uint8_t mac_addr[6])
{
    int i;
    for (i = 0; i < 5; ++i) {
        printf("%02x:", mac_addr[i]);
    }
    printf("%02x\n", mac_addr[5]);
}
#endif


/*
 *  Function for printing the arp-cache in debug mode
 *  @d  Pointer to struct containing all interfaces and sockets for this daemon
 */
#ifdef DEBUG
static void print_arp_cache(struct daemon *d)
{
    printf("\n----MIP-ARP-CACHE----\n");
    int i;
    for (i = 0; i < 256; i++) {
        if (d->arp_cache[i].mip_addr != 0) {
            printf("----MIP-ARP %d----\n", d->arp_cache[i].mip_addr);
            printf("MIP-Address: %d\n", d->arp_cache[i].mip_addr);
            print_mac_addr(d->arp_cache[i].mac_addr);
            printf("Raw socket: %d\n", d->arp_cache[i].raw_sock);
        }
    }
    printf("\n");
}
#endif


/*
 * Create unix socket
 * @fd_path     Path to the filedescriptor
 */
static int create_unix_socket(const char *fd_path)
{
    unlink(fd_path);

    int sock = socket(AF_UNIX, SOCK_SEQPACKET, 0);
    if (sock == -1) {
        perror("socket()");
        return -1;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));

    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, fd_path, sizeof(addr.sun_path) - 1);

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr))) {
        perror("bind()");
        return -1;
    }

    if (listen(sock, SOMAXCONN)) {
        perror("listen()");
        return -1;
    }
   
#ifdef DEBUG
    fprintf(stderr, "\n----NEW FILEDESCRIPTOR----\n");
    fprintf(stderr, "FD: %s, %d\n", fd_path, sock);
#endif
    return sock;

}


/*
 * Create raw socket for an interface
 * @interface   Interface to get MAC-Adress and raw socket for
 * @mip_addr    MIP-Address for this interface
 * @d           Pointer to struct containing all interfaces and sockets for this daemon
 * @index       Index of the interface-array in the dameon struct containing this interface
 */
static int create_raw_socket(const char *interface, int mip_addr, struct daemon *d, int index)
{

    int protocol = htons(ETH_P_ALL);
    int sock = socket(AF_PACKET, SOCK_RAW, protocol);
    if (sock == -1) {
        perror("socket()");
        exit(EXIT_FAILURE);
    }

    struct ifreq device;
    memset(&device, 0, sizeof(device));;
    
    strcpy(device.ifr_name, interface);
    
    if (ioctl(sock, SIOCGIFHWADDR, &device) == -1) {
        perror("ioctl()");
        exit(EXIT_FAILURE);
    }

    uint8_t mac_addr[6];
    memcpy(mac_addr, device.ifr_hwaddr.sa_data, 6);

#ifdef DEBUG
    fprintf(stderr, "\n----NEW MAC ADDRESS----\n");
    print_mac_addr(mac_addr);
#endif

    struct sockaddr_ll *dev;
    /* Fixes valgrind issues for bind(my_addr.sa_data) */
    struct sockaddr_storage storage;
    memset(&storage, 0, sizeof(storage));

    dev = (struct sockaddr_ll *)&storage;
    dev->sll_family = AF_PACKET;
    dev->sll_ifindex = if_nametoindex(interface);

    socklen_t addrlen = sizeof(struct sockaddr_ll);
    if (bind(sock, (struct sockaddr *)dev, addrlen) == -1) {
        perror("bind()");
        exit(EXIT_FAILURE);
    }
    
    /* Assign values to this interface */
    d->interfaces[index].mip_addr = mip_addr;
    memcpy(d->interfaces[index].mac_addr, mac_addr, 6);
    d->interfaces[index].raw_sock = sock;

    return sock;

}

/*
 *  Handle unix event
 *  @sock   The socket that recieves a connection
 *  @efd    The epoll file descriptor
 */
static int handle_unix_event(int sock, int efd)
{
    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));

    socklen_t addrlen = sizeof(addr);

    int conn_sock = accept(sock, (struct sockaddr *)&addr, &addrlen);
    if (conn_sock == -1) {
        perror("accept()");
        return -1;
    }

    ev.events = EPOLLIN;
    ev.data.fd = conn_sock;

    if (epoll_ctl(efd, EPOLL_CTL_ADD, conn_sock, &ev) == -1) {
        perror("epoll_ctl()");
        exit(EXIT_FAILURE);
    }

    return conn_sock;
}


/*
 *  Get interface for this daemon corresponding to a raw socket
 *  @raw_sock   The raw socket to be compared to all interfaces raw sockets
 *  @d          Pointer to struct containing all sockets and interfaces for this daemon
 */
static struct arp_entry *get_interface_raw(int raw_sock, struct daemon *d)
{
    int i;
    for (i = 0; d->interfaces[i].raw_sock != 0; i++) {
        if (d->interfaces[i].raw_sock == raw_sock) {
            return &(d->interfaces[i]);
        }
    }
    return NULL;
}


/*
 *  Check ARP-Cache for cached MIP-Daemons
 *  @mip_addr   MIP-Address for MIP-Daemon in question
 *  @d          Pointer to struct containing all sockets and interfaces for this daemon
 */
static int check_cache(int mip_addr, struct daemon *d)
{
    if (d->arp_cache[mip_addr].mip_addr == mip_addr)
        return 1;
    return 0;
}


/*
 *  Cache ARP-entry for a MIP-Daemon
 *  @f      Pointer to Ethernet-frame in the recieved packet
 *  @mip    Pointer to MIP-Header of Ethernet-frame in the recieved packet
 *  @iface  Pointer to interface with raw socket broadcasted to
 *  @d      Pointer to struct containing all socket and interfaces for this daemon
 */
static void cache_arp_entry(struct ethernet_frame *f, struct mip_header *mip, struct arp_entry *iface, struct daemon *d)
{   
    int mip_source = mip->mip_src;
    d->arp_cache[mip_source].mip_addr = mip->mip_src;
    memcpy(d->arp_cache[mip_source].mac_addr, f->src_mac, 6);
    d->arp_cache[mip_source].raw_sock = iface->raw_sock;
}


/*
 *  Creating MIP-Header for an ARP-Response
 *  @mip_addr   MIP-Address for the destination
 *  @iface      Pointer to the interface containing the source MIP-Address 
 */
static struct mip_header *mip_response(int mip_addr, struct arp_entry *iface)
{
    size_t size = sizeof(struct mip_header);
    struct mip_header *mip = malloc(size);

    mip->t = 0;
    mip->r = 0;
    mip->a = 0;
    mip->ttl = 15; /* Max value as default */
    mip->length = 0;
    mip->mip_src = iface->mip_addr;
    mip->mip_dst = mip_addr;
    
    return mip;
}


/*
 *  Create MIP-Header for transporting message
 *  @mip_addr   MIP-Address for the destination
 *  @iface      Pointer to the interface containing the source MIP-Address 
 *  @d          Pointer to struct containing the message to be sent
 */
static struct mip_header *mip_transport(int mip_addr, struct arp_entry *iface, struct daemon *d)
{
    size_t size = sizeof(struct mip_header) + d->frag_size;
    struct mip_header *mip = malloc(size);
    
    mip->t = 1;
    mip->r = 0;
    mip->a = 0;
    mip->ttl = 15; /* Max value as default  */
    mip->length = htons(d->frag_size);
    mip->mip_src = iface->mip_addr;
    mip->mip_dst = mip_addr;
    memcpy(mip->payload, d->pending_msg, d->frag_size);
    
    return mip;
}


/*
 *  Create MIP-Header for an ARP-Broadcast
 *  @mip_addr   MIP-Address for the destination
 *  @iface      Pointer to the interface containing the source MIP-Address 
 */
static struct mip_header *mip_broadcast(int mip_addr, struct arp_entry *iface)
{
    size_t size = sizeof(struct mip_header);
    struct mip_header *mip = malloc(size);

    mip->t = 0;
    mip->r = 0;
    mip->a = 1;
    mip->ttl = 15; /* Max value as default */
    mip->length = 0;
    mip->mip_src = iface->mip_addr;
    mip->mip_dst = mip_addr;

    return mip;
}


/*
 *  Send message, recieved over raw socket, to transport daemon 
 *  @message    Pointer to the message to be sent
 *  @d          Pointer to struct containing all interfaces and sockets for this daemon
 */
static int send_to_transport(struct daemon *d)
{
    struct msghdr msg; 
    memset(&msg, 0, sizeof(struct msghdr));
    struct iovec message_iov;
    memset(&message_iov, 0, sizeof(struct iovec));

    message_iov.iov_base = d->pending_msg;
    message_iov.iov_len = d->frag_size;

    msg.msg_iov = &message_iov;
    msg.msg_iovlen = 1;

    ssize_t ret = sendmsg(d->conn_sock_transport, &msg, 0);
    if (ret == -1) {
        perror("sendmsg()");
        return -1;
    }
    return 0;
}


/*
 *  Transmit package over raw socket
 *  @send_size      Size of the Ethernet-frame to be sent
 *  @mip_send       The MIP-Header for the Ethernet-frame
 *  @mac_addr       The MAC-Address for the destination interface
 *  @iface          Pointer to the interface the message is being sent from
 */
static int transmit(size_t send_size, struct mip_header *mip_send, uint8_t mac_addr[6], struct arp_entry *iface)
{
    struct ethernet_frame *frame = malloc(send_size);

    if (!frame) {
        perror("malloc()");
        return -1;
    }
    
    memcpy(frame->dst_mac, mac_addr, 6);
    memcpy(frame->src_mac, iface->mac_addr, 6);
    frame->ethernet_type = htons(0x88B5);
    memcpy(frame->data, mip_send, send_size - sizeof(struct ethernet_frame));

    ssize_t sent = send(iface->raw_sock, frame, send_size, 0);
    if (sent <= 0) {
        perror("send()");
        return -1;
    }

    free(frame);
    free(mip_send);

    return 0;
}


/*
 *  Function for checking the Ethernet-frame, and the TRA Bits of the MIP-Header, in the recieved packet
 *  @f      Recieved Ethernet-frame
 *  @iface  Interface the packet was recieved on
 *  @d      Pointer to struct containing all interfaces and sockets for this daemon
 */
static int check_frame(struct ethernet_frame *f, struct arp_entry *iface, struct daemon *d)
{   
    struct mip_header *mip = (struct mip_header *)f->data;
    struct mip_header *mip_send = NULL;
    size_t send_size = 0;

    if (iface->mip_addr != mip->mip_dst) {
        return -1;
    }
    
    if (mip->t == 0 && mip->r == 0 && mip->a == 1) {
        /* ARP Broadcast -> Store in cache -> Send ARP Response */
        cache_arp_entry(f, mip, iface, d);
#ifdef DEBUG
        fprintf(stderr, "Send ARP Response...\n");
#endif
        mip_send = mip_response(mip->mip_src, iface);
        send_size = sizeof(struct ethernet_frame) + sizeof(struct mip_header);

    } else if (mip->t == 0 && mip->r == 0 && mip->a == 0) {
        /* ARP Response -> Send package with payload */
        cache_arp_entry(f, mip, iface, d);
#ifdef DEBUG
        fprintf(stderr, "Transmit the payload...\n");
#endif
        mip_send = mip_transport(mip->mip_src, iface, d);
        send_size = sizeof(struct ethernet_frame) + sizeof(struct mip_header) + d->frag_size;
        
    } else if (mip->t == 1 && mip->r == 0 && mip->a == 0) {
        /* Transport -> Check cache for previous handshake */
        if (check_cache(mip->mip_src, d) == 0) {
#ifdef DEBUG
            fprintf(stderr, "MIP not cached... Ignoring...\n");
#endif
            return -1;
        }

        /* d->destination_mip = mip->mip_src; */
        d->last_received = mip->mip_src;
#ifdef DEBUG
        fprintf(stderr, "Payload revieced!\n");
#endif
        memcpy(d->pending_msg, mip->payload, d->frag_size);
        send_to_transport(d);

        return 1;

    } else if (mip->t == 0 && mip->r == 1 && mip->a == 0) {
        /* Routing */
    } else {
#ifdef DEBUG
        fprintf(stderr, "TRA Combination not recognized... Ignoring...\n");
#endif
    }

    transmit(send_size, mip_send, f->src_mac, iface);

    return 0;
}



/*
 *  Function for handling whatever is recieved over a raw socket
 *  @sock   The raw socket that recieves data
 *  @iface  The interface which the raw sock socket that recieves data is on
 *  @d      Pointer to struct containing all interfaces and sockets for this daemon
 */
static int handle_raw_event(int sock, struct arp_entry *iface, struct daemon *d)
{
    char buf[1600];
    memset(buf, 0, sizeof(buf));

    ssize_t ret = recv(sock, buf, sizeof(buf), 0);
    if (ret == -1) {
        perror("recv()");
        exit(EXIT_FAILURE);
    }
    
    if ((ret - sizeof(struct ethernet_frame) - sizeof(struct mip_header)) > 0) {
        d->frag_size = ret - sizeof(struct ethernet_frame) - sizeof(struct mip_header);
    }

    struct ethernet_frame *frame = (struct ethernet_frame *)buf;

    int check = check_frame(frame, iface, d);
    if (check == -1) {
        return -1;
    }

    return 0;
}


/*
 *  Sending ARP-broadcast message
 *  @iface  Broadcast on this interface
 *  @d      Pointer to struct containing all interfaces and sockets for this daemon
 */
static int broadcast_msg(struct arp_entry *iface, struct daemon *d)
{   
    
    struct mip_header *mip_a = mip_broadcast(d->destination_mip, iface);

    size_t broadcast_size = sizeof(struct ethernet_frame) + sizeof(struct mip_header);
    
    struct ethernet_frame *frame = malloc(broadcast_size);
    if (!frame) {
        perror("malloc()");
        return -1;
    }

    memcpy(frame->dst_mac, "\xff\xff\xff\xff\xff\xff", 6);
    memcpy(frame->src_mac, iface->mac_addr, 6);
    frame->ethernet_type = htons(0x88B5);
    memcpy(frame->data, mip_a, sizeof(struct mip_header));

    ssize_t sent = send(iface->raw_sock, frame, broadcast_size, 0);
    free(mip_a);
    if (sent <= 0) {
        perror("send()");
        return -1;
    }
#ifdef DEBUG
    fprintf(stderr, "Broadcasting...\n");
#endif
    free(frame);

    return 0;

}


/*
 *  Broadcast over each interface for this daemon
 *  @d      Pointer to struct containing all interfaces and sockets for this daemon
 */ 
static void broadcast_over_interfaces(struct daemon *d)
{  
    int i;
    for (i = 0; d->interfaces[i].mip_addr != 0; ++i) {
        broadcast_msg(&(d->interfaces[i]), d);
    } 
}


/*
 *  Function for making MIP-Header if MIP-Address for destination is cached
 *  @cache_entry    Cached interface
 *  @d              Pointer to struct containing all interfaces and sockets for this daemon
 */
static void make_transport(struct arp_entry *cache_entry, struct daemon *d)
{
    struct arp_entry *iface = get_interface_raw(cache_entry->raw_sock, d);
    if (!iface) {
#ifdef DEBUG
        fprintf(stderr, "Something went wrong... \n");
#endif
        return;
    }
    struct mip_header *mip_send = mip_transport(d->destination_mip, iface, d);
    size_t send_size = sizeof(struct ethernet_frame) + sizeof(struct mip_header) + d->frag_size;
    transmit(send_size, mip_send, cache_entry->mac_addr, iface);
}


/*
 *  Function for checking whether a message can be sent directly or if the daemon needs to send an ARP-broadcast message
 *  @d              Pointer to struct containing all interfaces and sockets for this daemon
 */
static void check_if_broadcast(struct daemon *d)
{   
    struct arp_entry *cache_entry = &(d->arp_cache[d->destination_mip]);
    if (cache_entry->raw_sock != 0) {
#ifdef DEBUG
        fprintf(stderr, "Destination is cached...\n");
        print_arp_cache(d);
#endif
        make_transport(cache_entry, d);
    } else {
#ifdef DEBUG
        fprintf(stderr, "Destination not cached...\n");
#endif
        broadcast_over_interfaces(d);
    }
}


/*
 *  Recieve message from client
 *  @conn_sock  The socket that the message from the client is recieved upon
 *  @d          Pointer to struct containing all interfaces and sockets for this daemon
 */
static void recieve_from_client(int conn_sock, struct daemon *d)
{
    int sock = conn_sock;
    
    /* msghdr struct for sendmsg/recvmsg */
    struct msghdr msg; 
    memset(&msg, 0, sizeof(struct msghdr));
    struct iovec message_iov[2];
    memset(&message_iov, 0, sizeof(struct iovec));

    char buf[1500];
    memset(&buf, 0, sizeof(buf));

    message_iov[1].iov_base = buf;
    message_iov[1].iov_len = sizeof(buf);

    int mip_addr;
    message_iov[0].iov_base = &mip_addr;
    message_iov[0].iov_len = sizeof(mip_addr);

    msg.msg_iov = message_iov;
    msg.msg_iovlen = 2;


    ssize_t ret = recvmsg(sock, &msg, 0);
    if (ret == -1) {
        perror("recvmsg()");
    }

    if (ret == 0) {
#ifdef DEBUG
        fprintf(stderr, "\n----CLIENT DISCONNECTED----\n");
        fprintf(stderr, "Client: %d\n", sock);
#endif
        close(sock);
    } else {
        strncpy(d->pending_msg, buf, sizeof(d->pending_msg) - strlen(d->pending_msg));
#ifdef DEBUG
        fprintf(stderr, "Message from client: %s\n", buf);
#endif
        d->destination_mip = mip_addr;
        check_if_broadcast(d);
    }
}


/*
 *  Recieve message from server
 *  @conn_sock  The socket that the message from the server is recieved upon
 *  @d          Pointer to struct containing all interfaces and sockets for this daemon
 */
static void recieve_from_server(int conn_sock, struct daemon *d)
{
    int sock = conn_sock;

    /* msghdr struct for sendmsg/recvmsg */
    struct msghdr msg; 
    memset(&msg, 0, sizeof(struct msghdr));
    struct iovec message_iov;
    memset(&message_iov, 0, sizeof(struct iovec));

    char buf[1500];
    memset(&buf, 0, sizeof(buf));

    message_iov.iov_base = buf;
    message_iov.iov_len = sizeof(buf);

    msg.msg_iov = &message_iov;
    msg.msg_iovlen = 1;

    ssize_t ret = recvmsg(sock, &msg, 0);
    if (ret == -1) {
        perror("recv()");
    }

    if (ret == 0) {
#ifdef DEBUG
        fprintf(stderr, "\n----SERVER DISCONNECTED----");
        fprintf(stderr, "Server: %d\n", sock);
#endif
        close(sock);
    } else {
        strncpy(d->pending_msg, buf, sizeof(d->pending_msg) - strlen(d->pending_msg));
#ifdef DEBUG
        fprintf(stderr, "Message from server: %s\n", buf);
#endif
        check_if_broadcast(d);
    }
}

static void recieve_from_transport(int sock, struct daemon *d)
{
    struct msghdr msg; 
    memset(&msg, 0, sizeof(struct msghdr));
    struct iovec message_iov[2];
    memset(&message_iov, 0, sizeof(struct iovec));

    uint8_t mip_addr;
    message_iov[0].iov_base = &mip_addr;
    message_iov[0].iov_len = sizeof(mip_addr);

    char buf[MAX_SIZE];
    memset(&buf, 0, sizeof(buf));

    message_iov[1].iov_base = buf;
    message_iov[1].iov_len = sizeof(buf);

    msg.msg_iov = message_iov;
    msg.msg_iovlen = 2;


    ssize_t ret = recvmsg(sock, &msg, 0);
    if (ret == -1) {
        perror("recvmsg()");
    }

    if (ret == 0) {
#ifdef DEBUG
        fprintf(stderr, "\n----TRANSPORT-DAEMON DISCONNECTED----\n");
        fprintf(stderr, "Transport: %d\n", sock);
#endif
        close(sock);
        return;
    }
#ifdef DEBUG
    fprintf(stderr, "Packet Recieved [%zd]\n", ret);
#endif
    if (mip_addr == 0) {
        d->destination_mip = d->last_received;
    } else {
        d->destination_mip = mip_addr;
    }

    d->frag_size = ret - 1;
    memcpy(d->pending_msg, buf, ret - 1);
    check_if_broadcast(d);
}


/*
 *  Function for handling events on the epoll filedescriptor
 *  @event  Socket that recieves data    
 *  @d      Pointer to struct containing all interfaces and sockets for this daemon
 */
static void handle_event(int event, struct daemon *d)
{
    if (event == d->client_sock) {
        int conn_sock_client = handle_unix_event(event, d->epollfd);

#ifdef DEBUG
        fprintf(stderr, "\n----CLIENT CONNECTED----\n");
        fprintf(stderr, "Client connection sock: %d\n", conn_sock_client);
#endif

        d->conn_sock_client = conn_sock_client;

    } else if (event == d->server_sock) {
        int conn_sock_server = handle_unix_event(event, d->epollfd);

#ifdef DEBUG
        fprintf(stderr, "\n----SERVER CONNECTED----\n");
        fprintf(stderr, "Server connection sock: %d\n", conn_sock_server);
#endif

        d->conn_sock_server = conn_sock_server;

    } else if (event == d->transport_sock) {
        int conn_sock_transport = handle_unix_event(event, d->epollfd);

#ifdef DEBUG
        fprintf(stderr, "\n----TRANSPORT-DAEMON CONNECTED----\n");
        fprintf(stderr, "Transport connection sock: %d\n", conn_sock_transport);
#endif

        d->conn_sock_transport = conn_sock_transport;

    } else if (event == d->conn_sock_client) {
        recieve_from_client(event, d);
    } else if (event == d->conn_sock_server) {
        recieve_from_server(event, d);
    } else if (event == d->conn_sock_transport) {
        recieve_from_transport(event, d);
    } else {
        int j;
        for (j = 0; d->interfaces[j].mip_addr != 0; ++j) {
            if (event == d->interfaces[j].raw_sock) {
                handle_raw_event(event, &(d->interfaces[j]), d);
            }
        }
    }

}


/*
 *  Main function for creating sockets and epoll file descriptor, and
 *  looping for connections on sockets
 */
int main(int argc, char* argv[])
{
    
    if (argc < 3) {
        printf("Usage: %s <Local Name> <Interface 1> <Address 1> --> <Interface N> <Address N>\n", argv[0]);
        exit(EXIT_FAILURE);
    }


    struct daemon daemon;
    memset(&daemon, 0, sizeof(struct daemon));

    char client_fd[20] = { 0 };
    char server_fd[20] = { 0 };
    char transport_fd[25] = { 0 };

    strncpy(client_fd, CLIENT_FD, sizeof(client_fd) - strlen(client_fd));
    strncpy(server_fd, SERVER_FD, sizeof(server_fd) - strlen(server_fd));
    strncpy(transport_fd, TRANSPORT_FD, sizeof(transport_fd) - strlen(transport_fd));

    strncat(client_fd, argv[1], sizeof(client_fd) - strlen(client_fd));
    strncat(server_fd, argv[1], sizeof(server_fd) - strlen(server_fd));
    strncat(transport_fd, argv[1], sizeof(transport_fd) - strlen(transport_fd));

    /* Create client socket */
    int client_sock = create_unix_socket(client_fd);
    if (client_sock == -1)
        exit(EXIT_FAILURE);

    /* Create server socket */
    int server_sock = create_unix_socket(server_fd);
    if (server_sock == -1)
        exit(EXIT_FAILURE);
    
    /* Create transport socket for transport daemon */
    int transport_sock = create_unix_socket(transport_fd);
    if (transport_sock == -1)
        exit(EXIT_FAILURE);

    /* Create raw sockets for each interface */
    int i;
    int j = 0;
    for (i = 2; i < argc; i+=2) {
        int mip = strtol(argv[i+1], NULL, 10);
        int raw_sock = create_raw_socket(argv[i], mip, &daemon, j);
        if (raw_sock == -1) {
            exit(EXIT_FAILURE);
        }
        j++;
    }
    

    struct epoll_event event, events[MAX_EVENTS];
    memset(&event, 0, sizeof(struct epoll_event));
        
    int epollfd = epoll_create1(0);
    if (epollfd == -1) {
        perror("epoll_create1()");
        exit(EXIT_FAILURE);
    }


    event.events = EPOLLIN;
    event.data.fd = client_sock;
    
    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, client_sock, &event) == -1) {
        perror("epoll_ctl()");
        exit(EXIT_FAILURE);
    }

    event.events = EPOLLIN;
    event.data.fd = server_sock;

    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, server_sock, &event) == -1) {
        perror("epoll_ctl()");
        exit(EXIT_FAILURE);
    }

    event.events = EPOLLIN;
    event.data.fd = transport_sock;

    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, transport_sock, &event) == -1) {
        perror("epoll_ctl()");
        exit(EXIT_FAILURE);
    }

    for (i = 0; i < j; i++) {
        int raw_sock = daemon.interfaces[i].raw_sock;
        event.events = EPOLLIN;
        event.data.fd = raw_sock;
        if (epoll_ctl(epollfd, EPOLL_CTL_ADD, raw_sock, &event) == -1) {
            perror("epoll_ctl()");
            exit(EXIT_FAILURE);
        }
    }


    daemon.epollfd = epollfd;
    daemon.client_sock = client_sock;
    daemon.server_sock = server_sock;
    daemon.transport_sock = transport_sock;
    
    for (;;) {

        int nfds = epoll_wait(epollfd, events, MAX_EVENTS, -1);
        if (nfds == -1) {
            perror("epoll_wait()");
            exit(EXIT_FAILURE);
        }
        
        int i;
        for (i = 0; i < nfds; ++i) {
            handle_event(events[i].data.fd, &daemon);
        }

    }

    close(daemon.epollfd);
    close(daemon.client_sock);
    close(daemon.server_sock);
    close(daemon.transport_sock);

    return 0;
}

