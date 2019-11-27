#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/epoll.h>
#include <sys/time.h>

#define DEBUG
#define CLIENT_FD "/tmp/client_fd_"

struct data_info {
    uint8_t mip_addr;
    uint16_t port;
}__attribute__((packed));

struct file_header {
    uint16_t file_size;
    char file_buf[];
}__attribute__((packed));


/*
 * Functon for connecting sockets to the MIPTP-Daemon
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

static void send_file(int sock, struct data_info *d, struct file_header *f)
{
    /* msghdr struct for sendmsg/recvmsg */
    struct msghdr msg; 
    memset(&msg, 0, sizeof(struct msghdr));
    struct iovec message_iov[2];
    memset(&message_iov, 0, sizeof(struct iovec));

    message_iov[0].iov_base = d;
    message_iov[0].iov_len = sizeof(struct data_info);

    message_iov[1].iov_base = f;
    message_iov[1].iov_len = sizeof(struct file_header) + f->file_size;

    msg.msg_iov = message_iov;
    msg.msg_iovlen = 2;

    ssize_t ret = sendmsg(sock, &msg, 0);
    if (ret == -1) {
        perror("sendmsg()");
        exit(EXIT_FAILURE);
    }
}

static struct file_header *get_file(char *path)
{
    FILE *fp;
    fp = fopen(path, "r");
    if (fp == NULL) {
        perror("fopen()");
        exit(EXIT_FAILURE);
    }

    fseek(fp, 0L, SEEK_END);
    long file_size = ftell(fp);
    rewind(fp);

    struct file_header *f = malloc(sizeof(struct file_header) + file_size);

    fread(f->file_buf, 1, file_size, fp);
    f->file_buf[file_size - 1] = 0;
    f->file_size = file_size;

    fclose(fp);

    return f;
}

/*
 *  Main function for creating socket, setting socket to timeout after 1 second, connecting
 *  to the local daemon, and waiting for a response
 */
int main(int argc, char *argv[])
{
    
    if (argc != 5) {
        printf("Usage: %s <Local Name> <Filename> <MIP Adress> <Portnumber>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    char client_fd[20] = { 0 };
    strncpy(client_fd, CLIENT_FD, sizeof(client_fd) - strlen(client_fd));
    strncat(client_fd, argv[1], sizeof(client_fd) - strlen(client_fd));

    int sock = connect_socket(client_fd);

    struct data_info d = { 0 };
    struct file_header *f = get_file(argv[2]);

    d.mip_addr = strtol(argv[3], NULL, 10); 
    d.port = strtol(argv[4], NULL, 10); 

    send_file(sock, &d, f);

    free(f);
    close(sock);

    return 0;
}
