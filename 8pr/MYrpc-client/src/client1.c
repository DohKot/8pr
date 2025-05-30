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
#define LOG_FILE_PATH "/var/log/myrpc.log"
#define MIN_PORT 1024
#define MAX_PORT 65535

typedef struct {
    char* remote_command;
    char* server_ip_address;
    int server_port_number;
    int connection_type;  // 1 = TCP, 0 = UDP
} ClientConfig;

typedef struct {
    struct sockaddr_in sender_info;
    socklen_t sender_info_len;
} UdpMetadata;

void show_usage_instructions() {
    printf("Remote Procedure Call Client\n");
    printf("Usage: rpc_client [OPTIONS]\n\n");
    printf("Options:\n");
    printf("  -c, --command \"command\"      Command to execute on server\n");
    printf("  -h, --host \"ip_address\"     Server IP address to connect\n");
    printf("  -p, --port PORT             Server port number (%d-%d)\n", MIN_PORT, MAX_PORT);
    printf("  -s, --stream                Use reliable TCP connection\n");
    printf("  -d, --dgram                 Use fast UDP datagrams\n");
    printf("      --help                  Show this help message\n");
}

int validate_network_port(int port) {
    return port >= MIN_PORT && port <= MAX_PORT;
}

int parse_command_arguments(int arg_count, char *arg_values[], ClientConfig *config) {
    static struct option options[] = {
        {"command", required_argument, NULL, 'c'},
        {"host", required_argument, NULL, 'h'},
        {"port", required_argument, NULL, 'p'},
        {"stream", no_argument, NULL, 's'},
        {"dgram", no_argument, NULL, 'd'},
        {"help", no_argument, NULL, 0},
        {NULL, 0, NULL, 0}
    };

    int opt;
    while ((opt = getopt_long(arg_count, arg_values, "c:h:p:sd", options, NULL)) != -1) {
        switch (opt) {
            case 'c': config->remote_command = optarg; break;
            case 'h': config->server_ip_address = optarg; break;
            case 'p': 
                config->server_port_number = atoi(optarg);
                if (!validate_network_port(config->server_port_number)) {
                    fprintf(stderr, "Error: Port must be between %d and %d\n", MIN_PORT, MAX_PORT);
                    return -1;
                }
                break;
            case 's': config->connection_type = 1; break;
            case 'd': config->connection_type = 0; break;
            case 0: show_usage_instructions(); return 1;
            default: return -1;
        }
    }

    if (!config->remote_command || !config->server_ip_address || !config->server_port_number) {
        fprintf(stderr, "Error: Missing required arguments\n");
        show_usage_instructions();
        return -1;
    }
    return 0;
}

int create_communication_socket(int use_tcp) {
    int sock_type;
    if (use_tcp) {
        sock_type = SOCK_STREAM;
    } else {
        sock_type = SOCK_DGRAM;
    }
    int sock = socket(AF_INET, sock_type, 0);
    
    if (sock < 0) {
        mysyslog("Network socket creation failed", ERROR, 0, 0, LOG_FILE_PATH);
        perror("socket");
    }
    return sock;
}

int setup_tcp_connection(int sock, struct sockaddr_in *server_addr) {
    if (connect(sock, (struct sockaddr*)server_addr, sizeof(*server_addr)) < 0) {
        mysyslog("TCP connection establishment failed", ERROR, 0, 0, LOG_FILE_PATH);
        perror("connect");
        return -1;
    }
    mysyslog("TCP connection successfully established", INFO, 0, 0, LOG_FILE_PATH);
    return 0;
}

void configure_server_address(const char *ip, int port, struct sockaddr_in *addr) {
    memset(addr, 0, sizeof(*addr));
    addr->sin_family = AF_INET;
    addr->sin_port = htons(port);
    inet_pton(AF_INET, ip, &addr->sin_addr);
}

int transmit_request(int sock, const char *request, 
                   struct sockaddr_in *server_addr, int is_tcp, 
                   UdpMetadata *udp_meta) {
    ssize_t sent_bytes;
    size_t request_len = strlen(request);

    if (is_tcp) {
        sent_bytes = send(sock, request, request_len, 0);
    } else {
        sent_bytes = sendto(sock, request, request_len, 0,
                          (struct sockaddr*)server_addr, sizeof(*server_addr));
        if (sent_bytes > 0) {
            udp_meta->sender_info_len = sizeof(udp_meta->sender_info);
        }
    }

    if (sent_bytes != (ssize_t)request_len) {
        mysyslog("Data transmission failed", ERROR, 0, 0, LOG_FILE_PATH);
        if (sent_bytes < 0) {
            perror("send");
        } else {
            perror("incomplete transmission");
        }
        return -1;
    }
    return 0;
}

int await_response(int sock, char *buffer, 
                  struct sockaddr_in *server_addr, int is_tcp,
                  UdpMetadata *udp_meta) {
    ssize_t received_bytes;

    if (is_tcp) {
        received_bytes = recv(sock, buffer, BUFFER_SIZE - 1, 0);
    } else {
        received_bytes = recvfrom(sock, buffer, BUFFER_SIZE - 1, 0,
                               (struct sockaddr*)&udp_meta->sender_info,
                               &udp_meta->sender_info_len);
    }

    if (received_bytes < 0) {
        mysyslog("Response reception failed", ERROR, 0, 0, LOG_FILE_PATH);
        perror("recv");
        return -1;
    }

    buffer[received_bytes] = '\0';
    
    if (!is_tcp) {
        char sender_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &udp_meta->sender_info.sin_addr, 
                 sender_ip, sizeof(sender_ip));
        mysyslog("Received UDP response", INFO, 0, 0, LOG_FILE_PATH);
        printf("Response from %s:%d\n", 
               sender_ip, ntohs(udp_meta->sender_info.sin_port));
    }
    
    return 0;
}

int main(int argc, char *argv[]) {
    ClientConfig config = {0};
    if (parse_command_arguments(argc, argv, &config) != 0) {
        return EXIT_FAILURE;
    }

    struct passwd *user = getpwuid(getuid());
    char request[BUFFER_SIZE];
    snprintf(request, sizeof(request), "%s: %s", user->pw_name, config.remote_command);

    mysyslog("Initializing client connection procedure", INFO, 0, 0, LOG_FILE_PATH);

    int sock = create_communication_socket(config.connection_type);
    if (sock < 0) return EXIT_FAILURE;

    struct sockaddr_in server_addr;
    configure_server_address(config.server_ip_address, 
                           config.server_port_number, &server_addr);

    if (config.connection_type && 
        setup_tcp_connection(sock, &server_addr) != 0) {
        close(sock);
        return EXIT_FAILURE;
    }

    UdpMetadata udp_meta = {0};
    if (transmit_request(sock, request, &server_addr, 
                       config.connection_type, &udp_meta) != 0) {
        close(sock);
        return EXIT_FAILURE;
    }

    char response[BUFFER_SIZE];
    if (await_response(sock, response, &server_addr, 
                     config.connection_type, &udp_meta) != 0) {
        close(sock);
        return EXIT_FAILURE;
    }

    printf("Server response content: %s\n", response);
    mysyslog("Server response processing complete", INFO, 0, 0, LOG_FILE_PATH);

    close(sock);
    return EXIT_SUCCESS;
}
