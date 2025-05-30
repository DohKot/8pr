#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <pwd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include "libmysyslog.h"

#define BUFFER_SIZE 1024
#define LOG_FILE "/var/log/myrpc.log"
#define MIN_PORT 1024
#define MAX_PORT 65535

typedef struct {
    struct sockaddr_in addr;
    socklen_t addr_len;
} UdpSenderInfo;

void print_help() {
    printf("Usage: myRPC-client [OPTIONS]\n");
    printf("Options:\n");
    printf("  -c, --command \"bash_command\"   Command to execute\n");
    printf("  -h, --host \"ip_addr\"          Server IP address\n");
    printf("  -p, --port PORT                Server port (%d-%d)\n", MIN_PORT, MAX_PORT);
    printf("  -s, --stream                   Use stream socket (TCP)\n");
    printf("  -d, --dgram                    Use datagram socket (UDP)\n");
    printf("      --help                     Display this help and exit\n");
}

int validate_port(int port) {
    if (port < MIN_PORT || port > MAX_PORT) {
        fprintf(stderr, "Error: Port must be between %d and %d\n", MIN_PORT, MAX_PORT);
        return 0;
    }
    return 1;
}

void log_error(const char *msg) {
    mysyslog(msg, ERROR, 0, 0, LOG_FILE);
    perror(msg);
}

int get_socket_type(int use_tcp) {
    if (use_tcp) {
        return SOCK_STREAM;
    }
    return SOCK_DGRAM;
}

int create_socket(int use_tcp) {
    int socket_type = get_socket_type(use_tcp);
    int sockfd = socket(AF_INET, socket_type, 0);
    if (sockfd < 0) {
        log_error("Socket creation failed");
    }
    return sockfd;
}

int establish_tcp_connection(int sockfd, struct sockaddr_in *serv_addr) {
    if (connect(sockfd, (struct sockaddr*)serv_addr, sizeof(*serv_addr)) < 0) {
        log_error("TCP connection failed");
        return 0;
    }
    mysyslog("TCP connection established", INFO, 0, 0, LOG_FILE);
    return 1;
}

const char* get_send_error_msg(ssize_t bytes_sent) {
    if (bytes_sent < 0) {
        return "send failed";
    }
    return "incomplete send";
}

int main(int argc, char *argv[]) {
    char *command = NULL;
    char *server_ip = NULL;
    int port = 0;
    int use_tcp = 1;

    static struct option long_options[] = {
        {"command", required_argument, 0, 'c'},
        {"host", required_argument, 0, 'h'},
        {"port", required_argument, 0, 'p'},
        {"stream", no_argument, 0, 's'},
        {"dgram", no_argument, 0, 'd'},
        {"help", no_argument, 0, 0},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "c:h:p:sd", long_options, NULL)) != -1) {
        switch (opt) {
            case 'c': command = optarg; break;
            case 'h': server_ip = optarg; break;
            case 'p': 
                port = atoi(optarg);
                if (!validate_port(port)) return EXIT_FAILURE;
                break;
            case 's': use_tcp = 1; break;
            case 'd': use_tcp = 0; break;
            case 0: print_help(); return EXIT_SUCCESS;
            default: print_help(); return EXIT_FAILURE;
        }
    }

    if (!command || !server_ip || port == 0) {
        fprintf(stderr, "Error: Required arguments missing\n");
        print_help();
        return EXIT_FAILURE;
    }

    struct passwd *user_info = getpwuid(getuid());
    char request[BUFFER_SIZE];
    snprintf(request, sizeof(request), "%s: %s", user_info->pw_name, command);

    mysyslog("Initializing client connection", INFO, 0, 0, LOG_FILE);

    int sockfd = create_socket(use_tcp);
    if (sockfd < 0) return EXIT_FAILURE;

    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, server_ip, &serv_addr.sin_addr) <= 0) {
        log_error("Invalid IP address");
        close(sockfd);
        return EXIT_FAILURE;
    }

    if (use_tcp) {
        if (!establish_tcp_connection(sockfd, &serv_addr)) {
            close(sockfd);
            return EXIT_FAILURE;
        }
    }

    ssize_t bytes_sent;
    size_t request_len = strlen(request);
    
    if (use_tcp) {
        bytes_sent = send(sockfd, request, request_len, 0);
    } else {
        bytes_sent = sendto(sockfd, request, request_len, 0,
                          (struct sockaddr*)&serv_addr, sizeof(serv_addr));
    }

    if (bytes_sent != (ssize_t)request_len) {
        const char *error_msg = get_send_error_msg(bytes_sent);
        log_error(error_msg);
        close(sockfd);
        return EXIT_FAILURE;
    }

    char response[BUFFER_SIZE];
    ssize_t bytes_received;
    UdpSenderInfo udp_info = {0};

    if (use_tcp) {
        bytes_received = recv(sockfd, response, BUFFER_SIZE - 1, 0);
    } else {
        udp_info.addr_len = sizeof(udp_info.addr);
        bytes_received = recvfrom(sockfd, response, BUFFER_SIZE - 1, 0,
                                (struct sockaddr*)&udp_info.addr, &udp_info.addr_len);
        
        char sender_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &udp_info.addr.sin_addr, sender_ip, INET_ADDRSTRLEN);
        printf("Response from: %s:%d\n", sender_ip, ntohs(udp_info.addr.sin_port));
    }

    if (bytes_received < 0) {
        log_error("recv failed");
        close(sockfd);
        return EXIT_FAILURE;
    }

    response[bytes_received] = '\0';
    printf("Server response: %s\n", response);
    mysyslog("Received server response", INFO, 0, 0, LOG_FILE);

    close(sockfd);
    return EXIT_SUCCESS;
}
