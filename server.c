#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/epoll.h>
#include <unistd.h>

#define DEBUG
#define MAX_SIZE 65535
#define MAX_PAYLOAD 1492

#define FILE_PREFIX "receivedFile"
#define SERVER_FD "/tmp/server_fd_"

struct server {
    struct node *root1;
    struct node *root2;
    uint8_t file_init1;
    uint8_t file_init2;
    uint16_t file_expected1;
    uint16_t file_expected2;
    uint16_t remaining;
};

struct server_header {
    uint16_t file_size;
    char file_buf[];
}__attribute__((packed));


struct file_data {
    uint16_t frag_len;
    char payload[];
};

struct node {
    struct node *next;
    struct file_data *data;
};

static struct node *free_list(struct node *root)
{
    struct node *curr, *temp;
    curr = root;
    while(curr != NULL) {
        temp = curr;
        curr = curr->next;
        free(temp->data);
        free(temp);
    }

    return NULL;
}


static void insert(struct file_data *data, struct node *root)
{
    struct node *curr;

    if (root->data == NULL) {
        root->data = data;
        root->next = NULL;
        return;
    }

    for (curr = root; curr->next != NULL; curr = curr->next) {
    }

    curr->next = (struct node *)malloc(sizeof(struct node));
    curr = curr->next;

    curr->data = data;
    curr->next = NULL;
}

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

static void send_port(int sock, uint16_t port1, uint16_t port2)
{
    /* msghdr struct for sendmsg/recvmsg */
    struct msghdr msg; 
    memset(&msg, 0, sizeof(struct msghdr));
    struct iovec message_iov[2];
    memset(&message_iov, 0, sizeof(struct iovec));

    message_iov[0].iov_base = &port1;
    message_iov[0].iov_len = sizeof(port1);

    message_iov[1].iov_base = &port2;
    message_iov[1].iov_len = sizeof(port2);

    msg.msg_iov = message_iov;
    msg.msg_iovlen = 2;

    ssize_t ret = sendmsg(sock, &msg, 0);
    if (ret == -1) {
        perror("sendmsg()");
        exit(EXIT_FAILURE);
    }
    
}

static void write_to_system(uint8_t file_num, struct server *s)
{
    struct node *root = s->root1;
    char file[s->file_expected1];
    memset(&file, 0, sizeof(file));

    void *offset = (void *)file;
    struct node *curr;
    uint16_t len = 0;
    /* uint16_t offset = 0 */
    for (curr = root; curr != NULL; curr = curr->next) {
        memcpy(offset, curr->data->payload, curr->data->frag_len);
        offset += curr->data->frag_len;
        len += curr->data->frag_len;
    }

    char file_name[16];
    snprintf(file_name, sizeof(file_name), "%s%d", FILE_PREFIX, file_num);
    FILE *fp;
    fp = fopen(file_name, "wb");
    if (fp == NULL) {
        perror("fopen()");
        exit(EXIT_FAILURE);
    }

#ifdef DEBUG
    fprintf(stderr, "Whole file recieved... Writing to system!\n");
#endif

    fwrite(file, 1, s->file_expected1, fp); 

    fclose(fp);

    free_list(root);
    
    exit(EXIT_SUCCESS);
}

static void receive_file(int sock, struct node *root, struct server *s)
{
    struct msghdr msg; 
    memset(&msg, 0, sizeof(struct msghdr));
    struct iovec message_iov;
    memset(&message_iov, 0, sizeof(struct iovec));

    char buf[MAX_PAYLOAD];
    memset(&buf, 0, sizeof(buf));

    message_iov.iov_base = buf;
    message_iov.iov_len = MAX_PAYLOAD;

    msg.msg_iov = &message_iov;
    msg.msg_iovlen = 1;


    ssize_t ret = recvmsg(sock, &msg, 0);
    if (ret == -1) {
        perror("recv()");
        exit(EXIT_FAILURE);
    }

    if (ret == 0) {
#ifdef DEBUG
        fprintf(stderr, "----TRANSPORT DAEMON DISCONNECTED----\n");
        fprintf(stderr, "Daemon: %d\n", sock);
#endif
        close(sock);
        return;
    }

    if (s->file_expected1 == 0) {
        struct server_header *server_head = malloc(ret);
        server_head = (struct server_header *)buf;
        s->file_expected1 = server_head->file_size;
        s->remaining = server_head->file_size;

        struct file_data *data = malloc(ret);
        data->frag_len = ret - sizeof(struct file_data);
        memcpy(data->payload, server_head->file_buf, ret - sizeof(struct file_data));

        insert(data, root);
        s->remaining -= ret - sizeof(struct file_data);
    } else {
       struct file_data *data = malloc(sizeof(struct file_data) + ret);
       data->frag_len = ret;
       memcpy(data->payload, buf, ret);

       insert(data, root);
       s->remaining -= ret;
    }

}


static void receive_loop(int sock)
{
    struct server s = { 0 };

    struct node *root1 = (struct node *)malloc(sizeof(struct node));
    root1->data = NULL;
    root1->next = NULL;

    struct node *root2 = (struct node *)malloc(sizeof(struct node));
    root2->data = NULL;
    root2->next = NULL;

    s.root1 = root1;    
    s.root2 = root2;    

    s.file_expected1 = 0;
    s.file_expected2 = 0;

    s.remaining = 0;

    uint8_t file_num = 1;

    for (;;) {
        receive_file(sock, root1, &s);

        if (s.remaining == 0) {
            write_to_system(file_num, &s);
            file_num++;
        }
    }
}


/*
 *  
 */
int main(int argc, char *argv[])
{
    if (argc < 3) {
        printf("Usage: %s <Local Name> <Port 1> (<Port 2>)\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    char server_fd[20] = { 0 };
    strncpy(server_fd, SERVER_FD, sizeof(server_fd) - strlen(server_fd));
    strncat(server_fd, argv[1], sizeof(server_fd) - strlen(server_fd));

    uint16_t port1 = strtol(argv[2], NULL, 10); 
    uint16_t port2 = 0; 
    if (argc == 4) {
        port2 = strtol(argv[3], NULL, 10); 
    }
    
    int sock = connect_socket(server_fd);

    send_port(sock, port1, port2);
    receive_loop(sock);

    return 0;
}
