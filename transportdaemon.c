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

#define MAX_PAYLOAD 1492
#define MAX_SIZE 65535
#define MAX_FRAGMENTS (65535 / 1492) + 1
#define MAX_EVENTS 12
#define MAX_SERVERS 10
#define WINDOW_SIZE 10
#define DEBUG

#define TRANSPORT_FD "/tmp/transport_fd_"
#define CLIENT_FD  "/tmp/client_fd_"
#define SERVER_FD  "/tmp/server_fd_"

struct server_data {
    int sock;
    uint8_t expected_seq;
    uint16_t port1;
    uint16_t port2;
};

struct fragment {
    uint8_t mip_addr;
    uint16_t frag_len;
    struct miptp_header *data;
};

struct transport_info {
    int epollfd;
    int transport_sock;
    int client_sock;
    int server_sock;

    int conn_sock_client;

    int timeout;

    uint8_t ant_packets;
    uint8_t packets_left;
    uint8_t waiting;
    uint8_t next;
     
    struct fragment packets[MAX_FRAGMENTS];
    struct server_data servers[MAX_SERVERS];
};


struct data_info {
    uint8_t mip_addr;
    uint16_t port;
    char file_buf[];
}__attribute__((packed));

struct miptp_header {
    uint8_t pl : 2;
    uint16_t port : 14;
    uint16_t seq;
    char payload[];
}__attribute__((packed));

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
 * Create unix socket
 * @fd_path     Path to the filedescriptor
 *
 * @return      New Unix socket
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
 *  Handle unix event
 *  @sock   The socket that recieves a connection
 *  @efd    The epoll file descriptor
 *
 *  @return Socket to send data on
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

static void send_packet(uint8_t index, struct transport_info *info)
{
    /* msghdr struct for sendmsg/recvmsg */
    struct msghdr msg; 
    memset(&msg, 0, sizeof(struct msghdr));
    struct iovec message_iov[2];
    memset(&message_iov, 0, sizeof(struct iovec));

    message_iov[0].iov_base = &(info->packets[index].mip_addr);
    message_iov[0].iov_len = sizeof(info->packets[index].mip_addr);

    message_iov[1].iov_base = info->packets[index].data;
    message_iov[1].iov_len = sizeof(struct miptp_header) + info->packets[index].frag_len;

    msg.msg_iov = message_iov;
    msg.msg_iovlen = 2;

    ssize_t ret = sendmsg(info->transport_sock, &msg, 0);
    if (ret == -1) {
        perror("sendmsg()");
        exit(EXIT_FAILURE);
    }
}

static void send_window(struct transport_info *info) {
    uint8_t start_seq = info->next;
    int i;
    uint8_t iterations = 0;


    if (info->packets_left < WINDOW_SIZE)
        iterations = info->packets_left;
    else
        iterations = WINDOW_SIZE;

    for (i = start_seq; i < start_seq+iterations; ++i) {
        send_packet(i, info);
        info->waiting++;
    }
}

static void make_header(int bytes, int seq, struct fragment *packet, void *file_displacer, struct data_info *d)
{
    struct miptp_header *miptp = malloc(sizeof(struct miptp_header) + bytes); 

    miptp->pl = 0;
    miptp->port = d->port;
    miptp->seq = seq;
    memcpy(miptp->payload, file_displacer, bytes);

    packet->mip_addr = d->mip_addr;
    packet->frag_len = bytes;
    packet->data = miptp;
}

static void make_packets(uint16_t payload_len, struct data_info *d, struct transport_info *info)
{
    int ant_packets = payload_len / MAX_PAYLOAD;
    int last_packet = payload_len % MAX_PAYLOAD;

    void *file_displacer = (void *)d->file_buf;
    int i;
    for (i = 0; i < ant_packets+1; ++i) {
        if (i == ant_packets) {
            make_header(last_packet, i, &(info->packets[i]), file_displacer, d);
        } else {
            make_header(MAX_PAYLOAD, i, &(info->packets[i]), file_displacer, d);
            file_displacer += MAX_PAYLOAD;
        }
    }

    info->ant_packets = ant_packets+1;
    info->packets_left = ant_packets+1;

    free(d);

}

static void recieve_from_client(int sock, struct transport_info *info)
{
    /* msghdr struct for sendmsg/recvmsg */
    struct msghdr msg; 
    memset(&msg, 0, sizeof(struct msghdr));
    struct iovec message_iov[2];
    memset(&message_iov, 0, sizeof(struct iovec));

    char struct_buf[sizeof(struct data_info)] = { 0 };
    char payload_buf[MAX_SIZE] = { 0 };

    message_iov[0].iov_base = struct_buf;
    message_iov[0].iov_len = sizeof(struct data_info);

    message_iov[1].iov_base = payload_buf;
    message_iov[1].iov_len = MAX_SIZE;

    msg.msg_iov = message_iov;
    msg.msg_iovlen = 2;

    ssize_t ret = recvmsg(sock, &msg, 0);
    if (ret == -1) {
        perror("recvmsg()");
        exit(EXIT_FAILURE);
    }
        
    if (ret == 0) {
#ifdef DEBUG
        fprintf(stderr, "----FILE TRANSFER CLIENT DISCONNECTED----\n");
        fprintf(stderr, "Client: %d\n", sock);
#endif
        close(sock);
        return;
    }

    struct data_info *d = malloc(ret);
    uint16_t payload_len = ret - sizeof(struct data_info);

    memcpy(d, struct_buf, sizeof(struct data_info));
    memcpy(d->file_buf, payload_buf, payload_len);

    make_packets(payload_len, d, info);
        
}

static void recieve_from_server(int sock, struct transport_info *info)
{
    /* msghdr struct for sendmsg/recvmsg */
    struct msghdr msg; 
    memset(&msg, 0, sizeof(struct msghdr));
    struct iovec message_iov[2];
    memset(&message_iov, 0, sizeof(struct iovec));

    uint16_t port1;
    uint16_t port2;

    message_iov[0].iov_base = &port1;
    message_iov[0].iov_len = sizeof(port1);

    message_iov[1].iov_base = &port2;
    message_iov[1].iov_len = sizeof(port2);

    msg.msg_iov = message_iov;
    msg.msg_iovlen = 2;

    ssize_t ret = recvmsg(sock, &msg, 0);
    if (ret == -1) {
        perror("recvmsg()");
        exit(EXIT_FAILURE);
    }
        
    if (ret == 0) {
#ifdef DEBUG
        fprintf(stderr, "----FILE TRANSFER SERVER DISCONNECTED----\n");
        fprintf(stderr, "Server: %d\n", sock);
#endif
        close(sock);
        return;
    }

    int i;
    for (i = 0; i < MAX_SERVERS; ++i) {
        if (info->servers[i].sock == sock) {
            info->servers[i].port1 = port1;
            if (port2 != 0) {
                info->servers[i].port2 = port2;
            }
        }
    }
}

static void send_to_server(int sock, uint16_t frag_len, struct miptp_header *miptp)
{
    struct msghdr msg; 
    memset(&msg, 0, sizeof(struct msghdr));
    struct iovec message_iov;
    memset(&message_iov, 0, sizeof(struct iovec));

    message_iov.iov_base = miptp->payload;
    message_iov.iov_len = frag_len;

    msg.msg_iov = &message_iov;
    msg.msg_iovlen = 1;

    ssize_t ret = sendmsg(sock, &msg, 0);
    if (ret == -1) {
        perror("sendmsg()");
        exit(EXIT_FAILURE);
    }
}


static void send_ack(uint16_t seq, struct transport_info *info)
{
    struct miptp_header *miptp = malloc(sizeof(struct miptp_header));
    miptp->pl = 0;
    miptp->port = 0;
    miptp->seq = seq;

    uint8_t ack_mip = 0;

    /* msghdr struct for sendmsg/recvmsg */
    struct msghdr msg; 
    memset(&msg, 0, sizeof(struct msghdr));
    struct iovec message_iov[2];
    memset(&message_iov, 0, sizeof(struct iovec));

    message_iov[0].iov_base = &(ack_mip);
    message_iov[0].iov_len = sizeof(uint8_t);

    message_iov[1].iov_base = miptp;
    message_iov[1].iov_len = sizeof(struct miptp_header);

    msg.msg_iov = message_iov;
    msg.msg_iovlen = 2;

    ssize_t ret = sendmsg(info->transport_sock, &msg, 0);
    if (ret == -1) {
        perror("sendmsg()");
        exit(EXIT_FAILURE);
    }
    free(miptp);
}

static void inspect_packet(uint16_t frag_len, struct miptp_header *miptp, struct transport_info *info)
{
    int sock = -1;
    uint16_t port = miptp->port;

    int i;
    for (i = 0; i < MAX_SERVERS; ++i) {
        if (info->servers[i].port1 == port) {
            sock = info->servers[i].sock;
            break;
        } else if (info->servers[i].port2 == port) {
            sock = info->servers[i].sock;
            break;
        }
    }

    if (miptp->seq > info->servers[i].expected_seq) {
#ifdef DEBUG
        fprintf(stderr, "Dropping packet with sequence number [%d]\n", miptp->seq);
#endif
        return;
    } else if (miptp->seq == info->servers[i].expected_seq) {
        send_to_server(sock, frag_len, miptp);
        info->servers[i].expected_seq++;
    }
    if (miptp->seq < info->servers[i].expected_seq) {
        send_ack(miptp->seq, info);
    }

}

static void received_ack(struct miptp_header *miptp, struct transport_info *info)
{
    if (miptp->seq >= info->next) {
        int difference = miptp->seq - info->next;
        info->next = miptp->seq+1;
        info->waiting -= difference + 1;
        info->packets_left = info->ant_packets - (miptp->seq + 1);
    }
}

static int handle_transport(int sock, struct transport_info *info)
{
    struct msghdr msg; 
    memset(&msg, 0, sizeof(struct msghdr));
    struct iovec message_iov;
    memset(&message_iov, 0, sizeof(struct iovec));

    char buf[MAX_PAYLOAD] = { 0 };

    message_iov.iov_base = buf;
    message_iov.iov_len = sizeof(struct miptp_header) + MAX_PAYLOAD;

    msg.msg_iov = &message_iov;
    msg.msg_iovlen = 1;

    ssize_t ret = recvmsg(sock, &msg, 0);
    if (ret == -1) {
        perror("recvmsg()");
        exit(EXIT_FAILURE);
    }

    if (ret == 0) {
#ifdef DEBUG
        fprintf(stderr, "----MIP-DAEMON DISCONNECTED----\n");
        fprintf(stderr, "Daemon: %d\n", sock);
#endif
        close(sock);
        return -1;
    }

    struct miptp_header *miptp = malloc(ret);
    memcpy(miptp, buf, ret);

    int status = 0;

    // Is ACK
    if (ret == 4) {
        received_ack(miptp, info);
        status = 1;
        return status;
    }

    uint16_t frag_len = ret - sizeof(struct miptp_header);
    inspect_packet(frag_len, miptp, info);

    return status;
}

/*
 *  Function for handling events on the epoll filedescriptor
 *  @event  Socket that recieves data    
 *  @info   Pointer to struct containing all interfaces and sockets for this daemon
 */
static void handle_event(int event, struct transport_info *info)
{
    if (event == info->client_sock) {
        int conn_sock_client = handle_unix_event(event, info->epollfd);
#ifdef DEBUG
        fprintf(stderr, "\n----FILE-TRANSFER-CLIENT CONNECTED----\n");
        fprintf(stderr, "Client connection sock: %d\n", conn_sock_client);
#endif
        info->conn_sock_client = conn_sock_client;

    } else if (event == info->server_sock) {
        int conn_sock_server = handle_unix_event(event, info->epollfd);
#ifdef DEBUG
        fprintf(stderr, "\n----FILE-TRANSFER-SERVER CONNECTED----\n");
        fprintf(stderr, "Server connection sock: %d\n", conn_sock_server);
#endif
        int i;
        for (i = 0; i < MAX_SERVERS; ++i) {
            if (info->servers[i].sock == -1) {
                info->servers[i].sock = conn_sock_server;
                break;
            }
        }
    } else if (event == info->conn_sock_client) {
        recieve_from_client(event, info);
    } else {
        int i;
        for (i = 0; i < MAX_SERVERS; ++i) {
            if (info->servers[i].sock == event) {
                recieve_from_server(event, info);
            }
        }
    } 
}

static int check_miptp(int event, struct transport_info *info)
{
    int is_tp = -1;
    if (event == info->transport_sock) {
        is_tp = handle_transport(event, info);
    }
    return is_tp;
}

int main(int argc, char *argv[])
{
    if (argc < 3) {
        printf("Usage: %s <Local Name> <Timeout>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    char transport_fd[25] = { 0 };
    char client_fd[25] = { 0 };
    char server_fd[25] = { 0 };

    struct transport_info info = { 0 };

    strncpy(transport_fd, TRANSPORT_FD, sizeof(transport_fd) - strlen(transport_fd));
    strncpy(client_fd, CLIENT_FD, sizeof(client_fd) - strlen(client_fd));
    strncpy(server_fd, SERVER_FD, sizeof(server_fd) - strlen(server_fd));

    strncat(transport_fd, argv[1], sizeof(transport_fd) - strlen(transport_fd));
    strncat(client_fd, argv[1], sizeof(client_fd) - strlen(client_fd));
    strncat(server_fd, argv[1], sizeof(server_fd) - strlen(server_fd));

    int transport_sock = connect_socket(transport_fd);

    /* Create client socket */
    int client_sock = create_unix_socket(client_fd);
    if (client_sock == -1)
        exit(EXIT_FAILURE);

    /* Create server socket */
    int server_sock = create_unix_socket(server_fd);
    if (server_sock == -1)
        exit(EXIT_FAILURE);

    struct epoll_event event, events[MAX_EVENTS];
    memset(&event, 0, sizeof(struct epoll_event));

    int epollfd = epoll_create1(0);
    if (epollfd == -1) {
        perror("epoll_create1()");
        exit(EXIT_FAILURE);
    }

    event.events = EPOLLIN;
    event.data.fd = transport_sock;

    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, transport_sock, &event) == -1) {
        perror("epoll_ctl()");
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

    info.timeout = strtol(argv[2], NULL, 10)*1000; 
    info.epollfd = epollfd;
    info.transport_sock = transport_sock;
    info.client_sock = client_sock;
    info.server_sock = server_sock;
    memset(info.packets, 0, sizeof(info.packets));
    memset(info.servers, 0, sizeof(info.servers));
    info.waiting = 0;

    int i;
    for (i = 0; i < MAX_SERVERS; ++i) {
        info.servers[i].sock = -1;
    }

    time_t start = time(NULL);
    time_t epoll_timeout;

    for (;;) {
        if (info.packets_left == 0) {
            epoll_timeout = -1;
        } else if (info.waiting < WINDOW_SIZE) {
            epoll_timeout = info.timeout;
        }

        int nfds = epoll_wait(epollfd, events, MAX_EVENTS, epoll_timeout);
        if (nfds == -1) {
            perror("epoll_wait()");
            exit(EXIT_FAILURE);
        }

        time_t now = time(NULL);
        if (nfds == 0) {
            printf("Timeout...\n");
            send_window(&info);
            epoll_timeout = info.timeout;
        } else {
            epoll_timeout = info.timeout - (now - start);
        }
        start = now;

        int i;
        int status;
        for (i = 0; i < nfds; ++i) {
            status = check_miptp(events[i].data.fd, &info);
            if (status == 1) {
                epoll_timeout = info.timeout;
                break;
            } else if (status == 0) {
                break;
            }
            handle_event(events[i].data.fd, &info);
        }
    }

    close(info.epollfd);
    close(info.transport_sock);
    close(info.client_sock);
    close(info.server_sock);

    return 0;
}
