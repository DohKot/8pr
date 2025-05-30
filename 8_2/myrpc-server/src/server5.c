#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <pwd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syslog.h>
#include <fcntl.h>
#include "config_parser.h"
#include "libmysyslog.h"

#define BUFFER_SIZE 1024
#define MAX_USERS 32
#define CONFIG_PATH "/etc/myRPC/myRPC.conf"
#define USERS_PATH "/etc/myRPC/users.conf"
#define LOG_PATH "/var/log/myrpc.log"
#define TEMPLATE_STDOUT "/tmp/myRPC_XXXXXX.stdout"
#define TEMPLATE_STDERR "/tmp/myRPC_XXXXXX.stderr"
#define PID_FILE "/var/run/myrpc.pid"

static volatile sig_atomic_t running = 1;

typedef struct {
    char users[MAX_USERS][32];
    int count;
} UserList;

void handle_signal(int sig) {
    running = 0;
}

void daemonize() {
    pid_t pid = fork();
    if (pid < 0) exit(EXIT_FAILURE);
    if (pid > 0) exit(EXIT_SUCCESS);

    if (setsid() < 0) exit(EXIT_FAILURE);

    signal(SIGCHLD, SIG_IGN);
    signal(SIGHUP, SIG_IGN);

    pid = fork();
    if (pid < 0) exit(EXIT_FAILURE);
    if (pid > 0) exit(EXIT_SUCCESS);

    umask(0);
    chdir("/");

    for (int fd = sysconf(_SC_OPEN_MAX); fd >= 0; fd--) {
        close(fd);
    }

    open("/dev/null", O_RDWR);
    dup(0);
    dup(0);
}

int create_pidfile() {
    FILE* file = fopen(PID_FILE, "w");
    if (!file) {
        syslog(LOG_ERR, "Failed to create PID file");
        return 0;
    }
    fprintf(file, "%d\n", getpid());
    fclose(file);
    return 1;
}

void remove_pidfile() {
    unlink(PID_FILE);
}

int check_running() {
    FILE* file = fopen(PID_FILE, "r");
    if (!file) return 0;

    pid_t pid;
    if (fscanf(file, "%d", &pid) == 1 && kill(pid, 0) == 0) {
        fclose(file);
        return 1;
    }
    fclose(file);
    return 0;
}

int load_users(UserList* list) {
    FILE* file = fopen(USERS_PATH, "r");
    if (!file) {
        syslog(LOG_ERR, "Failed to open users file");
        return 0;
    }

    char line[64];
    list->count = 0;

    while (fgets(line, sizeof(line), file) != NULL && list->count < MAX_USERS) {
        line[strcspn(line, "\n")] = 0;
        if (line[0] != '#' && line[0] != '\0') {
            strncpy(list->users[list->count], line, 31);
            list->users[list->count][31] = '\0';
            list->count++;
        }
    }

    fclose(file);
    return 1;
}

int is_user_allowed(const UserList* list, const char* user) {
    for (int i = 0; i < list->count; i++) {
        if (strcmp(list->users[i], user) == 0) {
            return 1;
        }
    }
    return 0;
}

int execute_command(const char* cmd, char* output, size_t size) {
    char stdout_path[sizeof(TEMPLATE_STDOUT) + 1];
    char stderr_path[sizeof(TEMPLATE_STDERR) + 1];

    strcpy(stdout_path, TEMPLATE_STDOUT);
    strcpy(stderr_path, TEMPLATE_STDERR);

    int stdout_fd = mkstemp(stdout_path);
    int stderr_fd = mkstemp(stderr_path);

    if (stdout_fd < 0 || stderr_fd < 0) {
        syslog(LOG_ERR, "Failed to create temp files");
        if (stdout_fd >= 0) {
            close(stdout_fd);
            unlink(stdout_path);
        }
        if (stderr_fd >= 0) {
            close(stderr_fd);
            unlink(stderr_path);
        }
        return 0;
    }

    close(stdout_fd);
    close(stderr_fd);

    char full_cmd[BUFFER_SIZE];
    snprintf(full_cmd, sizeof(full_cmd), "%s > %s 2> %s", cmd, stdout_path, stderr_path);

    int status = system(full_cmd);
    if (status != 0) {
        FILE* err_file = fopen(stderr_path, "r");
        if (err_file) {
            size_t len = fread(output, 1, size - 1, err_file);
            output[len] = '\0';
            fclose(err_file);
        }
        unlink(stdout_path);
        unlink(stderr_path);
        return 0;
    }

    FILE* out_file = fopen(stdout_path, "r");
    if (!out_file) {
        unlink(stdout_path);
        unlink(stderr_path);
        return 0;
    }

    size_t len = fread(output, 1, size - 1, out_file);
    output[len] = '\0';
    fclose(out_file);

    unlink(stdout_path);
    unlink(stderr_path);

    return 1;
}

int setup_socket(int port, int tcp) {
    int socket_type;
    if (tcp) {
        socket_type = SOCK_STREAM;
    }
    else {
        socket_type = SOCK_DGRAM;
    }

    int sock = socket(AF_INET, socket_type, 0);
    if (sock < 0) {
        syslog(LOG_ERR, "Socket creation failed");
        return -1;
    }

    int opt = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        close(sock);
        syslog(LOG_ERR, "Socket option failed");
        return -1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(sock);
        syslog(LOG_ERR, "Bind failed on port %d", port);
        return -1;
    }

    if (tcp && listen(sock, 5) < 0) {
        close(sock);
        syslog(LOG_ERR, "Listen failed");
        return -1;
    }

    return sock;
}

void process_request(int sock, int tcp, const struct sockaddr_in* addr, socklen_t len, const UserList* users) {
    char request[BUFFER_SIZE];
    ssize_t received;

    if (tcp) {
        received = recv(sock, request, sizeof(request), 0);
    }
    else {
        received = recvfrom(sock, request, sizeof(request), 0, (struct sockaddr*)addr, &len);
    }

    if (received <= 0) return;

    request[received] = '\0';
    syslog(LOG_INFO, "Processing request");

    char* user = strtok(request, ":");
    char* cmd = strtok(NULL, "");
    char response[BUFFER_SIZE];

    if (!user || !cmd) {
        strcpy(response, "Invalid request format");
    }
    else if (!is_user_allowed(users, user)) {
        snprintf(response, sizeof(response), "User %s not allowed", user);
        syslog(LOG_WARNING, "Unauthorized attempt by %s", user);
    }
    else if (!execute_command(cmd, response, sizeof(response))) {
        strcpy(response, "Command failed");
        syslog(LOG_ERR, "Command failed: %s", cmd);
    }
    else {
        syslog(LOG_INFO, "Command succeeded: %s", cmd);
    }

    if (tcp) {
        send(sock, response, strlen(response), 0);
    }
    else {
        sendto(sock, response, strlen(response), 0, (struct sockaddr*)addr, len);
    }
}

int main(int argc, char* argv[]) {
    openlog("myrpc", LOG_PID, LOG_DAEMON);

    if (check_running()) {
        syslog(LOG_ERR, "Service already running");
        closelog();
        exit(EXIT_FAILURE);
    }

    if (argc == 1 || strcmp(argv[1], "-f") != 0) {
        daemonize();
    }

    if (!create_pidfile()) {
        closelog();
        exit(EXIT_FAILURE);
    }

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    signal(SIGQUIT, handle_signal);

    Config config = parse_config(CONFIG_PATH);
    if (config.port <= 0) {
        syslog(LOG_ERR, "Invalid config");
        remove_pidfile();
        closelog();
        exit(EXIT_FAILURE);
    }

    UserList users;
    if (!load_users(&users)) {
        remove_pidfile();
        closelog();
        exit(EXIT_FAILURE);
    }

    int tcp = strcmp(config.socket_type, "stream") == 0;
    int sock = setup_socket(config.port, tcp);
    if (sock < 0) {
        remove_pidfile();
        closelog();
        exit(EXIT_FAILURE);
    }

    const char* proto;
    if (tcp) {
        proto = "TCP";
    }
    else {
        proto = "UDP";
    }
    syslog(LOG_INFO, "Server started on %d/%s", config.port, proto);

    while (running) {
        if (tcp) {
            struct sockaddr_in addr;
            socklen_t len = sizeof(addr);
            int client = accept(sock, (struct sockaddr*)&addr, &len);
            if (client < 0) continue;

            process_request(client, 1, &addr, len, &users);
            close(client);
        }
        else {
            process_request(sock, 0, NULL, 0, &users);
        }
    }

    close(sock);
    remove_pidfile();
    syslog(LOG_INFO, "Server stopped");
    closelog();

    return EXIT_SUCCESS;
}
