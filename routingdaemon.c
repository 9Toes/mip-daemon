#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/epoll.h>
#include <time.h>

#define MAX_EVENTS 10
#define DEBUG

#define FORWARDING_FD "/tmp/forwarding_fd_"
#define ROUTING_FD  "/tmp/routing_fd_"

struct routing_table {
    uint8_t to;
    uint8_t cost;
    int8_t next;
}__attribute__((packed));

struct routing_info {
    int epollfd;
    int forwarding_sock;
    int routing_sock;

    int initialized; /* Check if table is initialized */

    uint8_t mip_addrs[256];
    uint8_t recieved_on_mip[256];
    struct routing_table table[256];
};


/*
 *  Function for getting the number of interfaces on the MIP-Daemon corresponding to
 *  this Routing-Daemon
 *  @info       Pointer to struct containing information for this routing daemon
 */
static int get_interface_cnt(struct routing_info *info)
{
    int cnt = 0;
    while (info->mip_addrs[cnt] != 0) {
        cnt++;
    } 
    return cnt;
}


/*
 *  Function for printing the state of the current routing table
 *  @info       Pointer to struct containing information for this routing daemon
 */

#ifdef DEBUG
static void print_table(struct routing_info *info)
{
    int i;
    fprintf(stderr, "\n----ROUTING TABLE----\n");
    for (i = 0; i < 256; ++i) {
        if (info->table[i].to != 0) {
            fprintf(stderr, "To: %d\n", info->table[i].to);
            fprintf(stderr, "Cost: %d\n", info->table[i].cost);
            fprintf(stderr, "Next: %d\n", info->table[i].next);
        }
    }
    fprintf(stderr, "\n");
}
#endif


/*
 *  Function for creating tables to send following the Split Horizon rule.
 *  @mip_addr   Removing routes from the table that will be sent on this MIP-Address
 *  @info       Pointer to struct containing information for this routing daemon
 *
 *  @return     The finished product that can be sent on the interface corresponding to @mip_addr
 */
static struct routing_table *make_table(uint8_t mip_addr, struct routing_info *info)
{
    struct routing_table *table = malloc(sizeof(info->table));

    memcpy(table, &(info->table), sizeof(info->table));
    int i;
    for (i = 0; i < 256; ++i) {
        if (info->recieved_on_mip[i] == mip_addr && mip_addr != 0) {
            table[i].to = 0; 
            table[i].cost = 0; 
            table[i].next = 0; 
        }
    }
    return table;
}

/*
 *  Function for adding new routes recieved from neighbours, to the routing table 
 *  for this Routing-Daemon. Using the rules of DVR to set the lowest cost to a certain MIP-Address.
 *  @mip_dst    MIP-Address for the interface the table was recieved on
 *  @mip_src    MIP-Address for the interface the table was sent from
 *  @table      Routing table for neighbour
 *  @info       Pointer to struct containing information for this routing daemon
 */
static void update_table(uint8_t mip_dst, uint8_t mip_src, struct routing_table table[256], struct routing_info *info)
{
    int i;
    for (i = 0; i < 256; ++i) {
        if (table[i].to != 0) {
            if (table[i].cost < info->table[i].cost) {
                info->table[i].to = table[i].to;
                info->table[i].cost = table[i].cost + 1;
                info->recieved_on_mip[i] = mip_dst;

                if (table[i].next == -1) {
                    info->table[i].next = mip_src;
                } else if (table[i].next == 0) {
                    info->table[i].next = -1;
                }
            }
        }
    }
    
}

/*
 *  Function for sendig routing table. Makes tables following the Split Horizon rule
 *  before sending them to the MIP-Daemon.
 *  @info       Pointer to struct containing information for this routing daemon
 */

static void send_table(struct routing_info *info)
{
    int iface_cnt = get_interface_cnt(info); 
    if (iface_cnt == 0) {
#ifdef DEBUG
        fprintf(stderr, "Something went wrong...\n");
#endif
        return;
    }

    int iovec_cnt = iface_cnt * 2;

    struct msghdr msg;
    memset(&msg, 0, sizeof(struct msghdr));
    struct iovec message_iov[iovec_cnt];
    memset(&message_iov, 0, sizeof(struct iovec));

    uint8_t mip_addr = 0;
    int index = 0;
    int i;
    for (i = 0; i < iovec_cnt; i+=2) {

        mip_addr = info->mip_addrs[index];

        message_iov[i].iov_base = make_table(mip_addr, info);
        message_iov[i].iov_len = sizeof(info->table);

        message_iov[i+1].iov_base = &(info->mip_addrs[index]); 
        message_iov[i+1].iov_len = sizeof(info->mip_addrs[index]);

        index++;
    }

    msg.msg_iov = message_iov;
    msg.msg_iovlen = iovec_cnt;

    ssize_t ret = sendmsg(info->routing_sock, &msg, 0);
    if (ret == -1) {
        perror("sendmsg()");
        return;
    }

    for (i = 0; i < iovec_cnt; i+=2) {
        free(message_iov[i].iov_base);
    }
}


/*
 *  Function for recieving routing updates, and passing them on.
 *  @sock   Socket for recieving updates upon
 *  @info       Pointer to struct containing information for this routing daemon
 */

static void recieve_update(int sock, struct routing_info *info)
{
    struct msghdr msg;
    memset(&msg, 0, sizeof(struct msghdr));
    struct iovec message_iov[3];
    memset(&message_iov, 0, sizeof(struct iovec));

    uint8_t mip_dst;
    uint8_t mip_src;
    struct routing_table table[256];
    memset(&table, 0, sizeof(table));

    message_iov[0].iov_base = &table;
    message_iov[0].iov_len = sizeof(table);

    message_iov[1].iov_base = &mip_dst;
    message_iov[1].iov_len = sizeof(mip_dst);

    message_iov[2].iov_base = &mip_src;
    message_iov[2].iov_len = sizeof(mip_src);

    msg.msg_iov = message_iov;
    msg.msg_iovlen = 3;

    ssize_t ret = recvmsg(sock, &msg, 0);
    if (ret == -1) {
        perror("recvmsg()");
    }

    if (ret == 0) {
#ifdef DEBUG
        fprintf(stderr, "\n----MIP-DAEMON ROUTING DISCONNECTED----");
        fprintf(stderr, "Routing: %d ", sock);
#endif
        close(sock);
        return;
    }
    update_table(mip_dst, mip_src, table, info);
}

/*
 *  Function for initializing the routing table with MIP-Addresses of the MIP-Daemon
 *  corresponding to this Routing-Daemon
 *  @sock   Socket that the Addresses is recieved upon
 *  @info       Pointer to struct containing information for this routing daemon
 */

static void initialize_table(int sock, struct routing_info *info)
{
    struct msghdr msg; 
    memset(&msg, 0, sizeof(struct msghdr));
    struct iovec message_iov[256];
    memset(&message_iov, 0, sizeof(struct iovec));
    
    int i;
    for (i = 0; i < 256; i++) {
        message_iov[i].iov_base = &(info->mip_addrs[i]);
        message_iov[i].iov_len = sizeof(info->mip_addrs[i]);
    }

    msg.msg_iov = message_iov;
    msg.msg_iovlen = i;

    ssize_t ret = recvmsg(sock, &msg, 0);
    if (ret == -1) {
        perror("recvmsg()");
    }

    if (ret == 0) {
        close(sock);
        return;
    }

    for (i = 0; i < 256; ++i) {
        info->table[i].cost = sizeof(uint8_t) + 1; /* Setting cost to "infinite" (1 more than possible paths) */
    }

    for (i = 0; i < ret; i++) {
        uint8_t index = info->mip_addrs[i];
        info->table[index].to = index;
        info->table[index].cost = 0;
    }

    info->initialized = 1;
}

/*
 *  Function for sending forwarding MIP-Address
 *  @mip_ret    MIP-Address that is next hop / message will be forwarded to
 *  @sock       Socket to send forwarding MIP-Address on
 */

static void send_forwarding_mip(uint8_t mip_ret, int sock)
{

    struct msghdr msg; 
    memset(&msg, 0, sizeof(struct msghdr));
    struct iovec message_iov;
    memset(&message_iov, 0, sizeof(struct iovec));

    message_iov.iov_base = &mip_ret;
    message_iov.iov_len = sizeof(uint8_t);

    msg.msg_iov = &message_iov;
    msg.msg_iovlen = 1;

    ssize_t ret = sendmsg(sock, &msg, 0);
    if (ret == -1) {
        perror("sendmsg()");
    }

}

/*
 *  Function for recieving forwarding information, and passing on the right MIP-Address
 *  @sock   Socket that information is recieved upon
 *  @info       Pointer to struct containing information for this routing daemon
 */

static void get_forwarding(int sock, struct routing_info *info)
{
    uint8_t mip_dst;
    struct msghdr msg; 
    memset(&msg, 0, sizeof(struct msghdr));
    struct iovec message_iov;
    memset(&message_iov, 0, sizeof(struct iovec));

    message_iov.iov_base = &mip_dst;
    message_iov.iov_len = sizeof(mip_dst);

    msg.msg_iov = &message_iov;
    msg.msg_iovlen = 1;

    ssize_t ret = recvmsg(sock, &msg, 0);
    if (ret == -1) {
        perror("recvmsg()");
    }

    if (info->table[mip_dst].cost == 0) 
        send_forwarding_mip(0, sock);
    else if (info->table[mip_dst].cost > 1 && info->table[mip_dst].next > 0)
        send_forwarding_mip(info->table[mip_dst].next, sock);
    else if (info->table[mip_dst].cost == sizeof(uint8_t) + 1)
        send_forwarding_mip(0, sock);
    else if (info->table[mip_dst].next == -1)
        send_forwarding_mip(info->table[mip_dst].to, sock);
}


/*
 *  Function for handling epoll events. Initializes routing table if not
 *  already initialized, else it updates the table.
 *  @event      The socket that recieves data
 *  @info       Pointer to struct containing information for this routing daemon
 */
static void handle_event(int event, struct routing_info *info)
{
    if (event == info->forwarding_sock) {
        get_forwarding(event, info);
    } else if (event == info->routing_sock) {
        if (info->initialized == 0) {
            initialize_table(event, info);
        } else {
            recieve_update(event, info);
        }
    }
}

/*
 * Functon for connecting sockets to the MIP-Daemon
 * @fd_path     Path to filedescriptor to connect on
 *  
 * @return      Connection socket for the filedescriptor in question
 */
static int connect_socket(const char *fd_path)
{
    int sock = socket(AF_UNIX, SOCK_SEQPACKET, 0);
    if (sock == -1) {
        perror("socket()");
        return -1;
    }

    struct sockaddr_un unix_addr = { 0 };
    unix_addr.sun_family = AF_UNIX;
    strncpy(unix_addr.sun_path, fd_path, sizeof(unix_addr.sun_path) - 1);
    
    if (connect(sock, (struct sockaddr *)&unix_addr, sizeof(unix_addr))) {
        perror("connect()");
        return -1;
    }
    
    return sock;
}


/*
 *  Main function for creating sockets and epoll file descriptor, looping
 *  for connections on sockets, and periodically send routing tables
 */
int main(int argc, char *argv[])
{
    if (argc < 2) {
        printf("Usage: %s <Local Name>\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    
    char forwarding_fd[25] = { 0 };
    char routing_fd[25] = { 0 };

    struct routing_info info = { 0 };
    info.initialized = 0;

    strncpy(forwarding_fd, FORWARDING_FD, sizeof(forwarding_fd) - strlen(forwarding_fd));
    strncpy(routing_fd, ROUTING_FD, sizeof(routing_fd) - strlen(routing_fd));

    strncat(forwarding_fd, argv[1], sizeof(forwarding_fd) - strlen(forwarding_fd));
    strncat(routing_fd, argv[1], sizeof(routing_fd) - strlen(routing_fd));

    int forwarding_sock = connect_socket(forwarding_fd);
    int routing_sock = connect_socket(routing_fd);

    struct epoll_event event, events[MAX_EVENTS];
    memset(&event, 0, sizeof(struct epoll_event));

    int epollfd = epoll_create1(0);
    if (epollfd == -1) {
        perror("epoll_create1()");
        exit(EXIT_FAILURE);
    }

    event.events = EPOLLIN;
    event.data.fd = forwarding_sock;

    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, forwarding_sock, &event) == -1) {
        perror("epoll_ctl()");
        exit(EXIT_FAILURE);
    }

    event.events = EPOLLIN;
    event.data.fd = routing_sock;

    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, routing_sock, &event) == -1) {
        perror("epoll_ctl()");
        exit(EXIT_FAILURE);
    }

    info.epollfd = epollfd;
    info.forwarding_sock = forwarding_sock;
    info.routing_sock = routing_sock;

    time_t start = time(NULL);
    time_t timeout = 10000;

    
    /* Epoll containing timeout for epoll_wait()
     * If there is an event on the epollfd, the timeout
     * is being calculated to run for the time remaining of the timeout
     * so that the incomming events doesn't block routing
     */
    for (;;) {

        int nfds = epoll_wait(epollfd, events, MAX_EVENTS, timeout);
        if (nfds == -1) {
            perror("epoll_wait()");
            exit(EXIT_FAILURE);
        }

        time_t now = time(NULL);

        if (nfds == 0) {
#ifdef DEBUG
            print_table(&info);
#endif
            send_table(&info);
            timeout = 10000;
        } else {
            timeout = 10000 - ((now - start) * 1000);
        }

        start = now;

        int i;
        for (i = 0; i < nfds; ++i) {
            handle_event(events[i].data.fd, &info);
        }

    }
    
    close(info.epollfd);
    close(info.forwarding_sock);
    close(info.routing_sock);

    return 0;
}
