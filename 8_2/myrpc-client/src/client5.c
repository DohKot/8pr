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
    char* command;
    char* host;
    int port;
    int use_tcp;
} ClientOptions;

void print_usage() {
    printf("Usage: rpcclient -c COMMAND -h HOST -p PORT [-s|-d]\n");
    printf("  -c, --command  Command to execute\n");
    printf("  -h, --host     Server IP\n");
    printf("  -p, --port     Server port (%d-%d)\n", MIN_PORT, MAX_PORT);
    printf("  -s, --stream   Use TCP (default)\n");
    printf("  -d, --dgram    Use UDP\n");
}

int parse_args(int argc, char* argv[], ClientOptions* opts) {
    int opt;
    opts->use_tcp = 1; // TCP ïî óìîë÷àíèþ

    while ((opt = getopt(argc, argv, "c:h:p:sd")) != -1) {
        switch (opt) {
        case 'c': opts->command = optarg; break;
        case 'h': opts->host = optarg; break;
        case 'p':
            opts->port = atoi(optarg);
            if (opts->port < MIN_PORT || opts->port > MAX_PORT) {
                fprintf(stderr, "Port must be between %d and %d\n", MIN_PORT, MAX_PORT);
                return -1;
            }
            break;
        case 's': opts->use_tcp = 1; break;
        case 'd': opts->use_tcp = 0; break;
        default:
            print_usage();
            return -1;
        }
    }

    if (!opts->command || !opts->host || !opts->port) {
        fprintf(stderr, "Missing required arguments\n");
        print_usage();
        return -1;
    }
    return 0;
}

int main(int argc, char* argv[]) {
    ClientOptions opts = { 0 };
    if (parse_args(argc, argv, &opts)) {
        return EXIT_FAILURE;
    }

    struct passwd* user = getpwuid(getuid());
        char request[BUFFER_SIZE];
        snprintf(request, sizeof(request), "%s: %s", user->pw_name, opts.command);

        mysyslog("Client started", INFO, 0, 0, LOG_FILE);

        int sock = socket(AF_INET, opts.use_tcp ? SOCK_STREAM : SOCK_DGRAM, 0);
        if (sock < 0) {
            perror("socket");
            mysyslog("Socket error", ERROR, 0, 0, LOG_FILE);
            return EXIT_FAILURE;
        }

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(opts.port)
    };
    if (inet_pton(AF_INET, opts.host, &addr.sin_addr) <= 0) {
        perror("inet_pton");
        mysyslog("Invalid IP", ERROR, 0, 0, LOG_FILE);
        close(sock);
        return EXIT_FAILURE;
    }

    if (opts.use_tcp && connect(sock, (struct sockaddr*)&addr, sizeof(addr))) {
        perror("connect");
        mysyslog("Connect failed", ERROR, 0, 0, LOG_FILE);
        close(sock);
        return EXIT_FAILURE;
    }

    ssize_t sent = opts.use_tcp
        ? send(sock, request, strlen(request), 0)
        : sendto(sock, request, strlen(request), 0, (struct sockaddr*)&addr, sizeof(addr));

    if (sent != (ssize_t)strlen(request)) {
        perror(sent < 0 ? "send" : "incomplete send");
        mysyslog("Send failed", ERROR, 0, 0, LOG_FILE);
        close(sock);
        return EXIT_FAILURE;
    }

    char response[BUFFER_SIZE];
    ssize_t received;
    struct sockaddr_in udp_addr;
    socklen_t udp_len = sizeof(udp_addr);

    received = opts.use_tcp
        ? recv(sock, response, BUFFER_SIZE - 1, 0)
        : recvfrom(sock, response, BUFFER_SIZE - 1, 0, (struct sockaddr*)&udp_addr, &udp_len);

    if (received < 0) {
        perror("recv");
        mysyslog("Receive error", ERROR, 0, 0, LOG_FILE);
        close(sock);
        return EXIT_FAILURE;
    }

    response[received] = '\0';

    if (!opts.use_tcp && received > 0) {
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &udp_addr.sin_addr, ip_str, sizeof(ip_str));
        printf("UDP response from %s:%d\n", ip_str, ntohs(udp_addr.sin_port));
    }

    printf("Response: %s\n", response);
    mysyslog("Response received", INFO, 0, 0, LOG_FILE);

    close(sock);
    return EXIT_SUCCESS;
}
