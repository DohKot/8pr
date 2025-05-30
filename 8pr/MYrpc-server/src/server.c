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
#include <sys/file.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>
#include <sys/wait.h>
#include "config_parser.h"
#include "libmysyslog.h"

#define BUFFER_SIZE 1024
#define MAX_CMD_LEN 8192
#define MAIN_CONFIG "/etc/myRPC/myRPC.conf"
#define USERS_CONFIG "/etc/myRPC/users.conf"
#define LOG_FILE "/var/log/myrpc.log"
#define PID_FILE "/var/run/myrpc.pid"
#define TEMPLATE_STDOUT "/tmp/myRPC_XXXXXX.stdout"
#define TEMPLATE_STDERR "/tmp/myRPC_XXXXXX.stderr"

volatile sig_atomic_t stop;

typedef struct {
    char stdout_path[PATH_MAX];
    char stderr_path[PATH_MAX];
    int stdout_fd;
    int stderr_fd;
} TempFiles;

void create_pidfile() {
    int pid_fd = open(PID_FILE, O_RDWR|O_CREAT, 0644);
    if (pid_fd == -1) {
        mysyslog("Failed to create PID file", ERROR, 0, 0, LOG_FILE);
        exit(EXIT_FAILURE);
    }
    
    if (lockf(pid_fd, F_TLOCK, 0) == -1) {
        if (errno == EAGAIN || errno == EACCES) {
            mysyslog("Daemon already running", ERROR, 0, 0, LOG_FILE);
        } else {
            mysyslog("PID file lock failed", ERROR, 0, 0, LOG_FILE);
        }
        close(pid_fd);
        exit(EXIT_FAILURE);
    }
    
    char pid_str[16];
    int pid_len = snprintf(pid_str, sizeof(pid_str), "%d", getpid());
    ftruncate(pid_fd, 0);
    write(pid_fd, pid_str, pid_len);
}

void remove_pidfile() {
    unlink(PID_FILE);
}

void daemonize() {
    pid_t pid = fork();
    if (pid < 0) {
        mysyslog("Fork failed", ERROR, 0, 0, LOG_FILE);
        exit(EXIT_FAILURE);
    }
    if (pid > 0) {
        exit(EXIT_SUCCESS);
    }
    
    if (setsid() < 0) {
        mysyslog("setsid failed", ERROR, 0, 0, LOG_FILE);
        exit(EXIT_FAILURE);
    }
    
    umask(0);
    if (chdir("/") < 0) {
        mysyslog("chdir failed", ERROR, 0, 0, LOG_FILE);
        exit(EXIT_FAILURE);
    }
    
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
    
    if (open("/dev/null", O_RDONLY) == -1) {
        mysyslog("Failed to reopen stdin", ERROR, 0, 0, LOG_FILE);
    }
    if (open("/dev/null", O_WRONLY) == -1) {
        mysyslog("Failed to reopen stdout", ERROR, 0, 0, LOG_FILE);
    }
    if (open("/dev/null", O_WRONLY) == -1) {
        mysyslog("Failed to reopen stderr", ERROR, 0, 0, LOG_FILE);
    }
    
    create_pidfile();
}

void handle_signal(int sig) {
    stop = 1;
}

int user_allowed(const char *username) {
    Config config = parse_config(USERS_CONFIG);
    int allowed = 0;
    
    if (strlen(config.user)) {
        if (strcmp(config.user, username) == 0) {
            allowed = 1;
        }
    }
    
    if (!allowed) {
        for (size_t i = 0; i < config.users_count; i++) {
            if (strcmp(config.users[i], username) == 0) {
                allowed = 1;
                break;
            }
        }
    }
    
    return allowed;
}

int create_temp_files(TempFiles *files) {
    strcpy(files->stdout_path, TEMPLATE_STDOUT);
    strcpy(files->stderr_path, TEMPLATE_STDERR);
    
    files->stdout_fd = mkstemps(files->stdout_path, 7);
    if (files->stdout_fd == -1) {
        mysyslog("Failed to create stdout temp file", ERROR, 0, 0, LOG_FILE);
        return -1;
    }
    fchmod(files->stdout_fd, 0600);
    
    files->stderr_fd = mkstemps(files->stderr_path, 7);
    if (files->stderr_fd == -1) {
        mysyslog("Failed to create stderr temp file", ERROR, 0, 0, LOG_FILE);
        close(files->stdout_fd);
        unlink(files->stdout_path);
        return -1;
    }
    fchmod(files->stderr_fd, 0600);
    
    return 0;
}

void cleanup_temp_files(TempFiles *files) {
    if (files->stdout_fd != -1) {
        close(files->stdout_fd);
    }
    if (files->stderr_fd != -1) {
        close(files->stderr_fd);
    }
    unlink(files->stdout_path);
    unlink(files->stderr_path);
}

int safe_execute(const char *command, const char *stdout_path, const char *stderr_path) {
    pid_t pid = fork();
    if (pid == -1) {
        mysyslog("Fork failed for command execution", ERROR, 0, 0, LOG_FILE);
        return -1;
    }
    
    if (pid == 0) {
        int out_fd = open(stdout_path, O_WRONLY);
        int err_fd = open(stderr_path, O_WRONLY);
        
        if (out_fd == -1 || err_fd == -1) {
            _exit(EXIT_FAILURE);
        }
        
        dup2(out_fd, STDOUT_FILENO);
        dup2(err_fd, STDERR_FILENO);
        
        execl("/bin/sh", "sh", "-c", command, NULL);
        _exit(EXIT_FAILURE);
    }
    
    int status;
    waitpid(pid, &status, 0);
    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    }
    return -1;
}

int execute_command(const char *command, char *response, size_t response_size) {
    if (strlen(command) > MAX_CMD_LEN - 100) {
        mysyslog("Command too long", ERROR, 0, 0, LOG_FILE);
        return -1;
    }
    
    TempFiles files;
    files.stdout_fd = -1;
    files.stderr_fd = -1;
    
    if (create_temp_files(&files)) {
        return -1;
    }
    
    int ret = safe_execute(command, files.stdout_path, files.stderr_path);
    if (ret == -1) {
        mysyslog("Command execution failed", ERROR, 0, 0, LOG_FILE);
        cleanup_temp_files(&files);
        return -1;
    }
    
    FILE *fp = fopen(files.stdout_path, "r");
    if (!fp) {
        mysyslog("Failed to open stdout file", ERROR, 0, 0, LOG_FILE);
        cleanup_temp_files(&files);
        return -1;
    }
    
    size_t read_bytes = fread(response, 1, response_size - 1, fp);
    response[read_bytes] = '\0';
    fclose(fp);
    
    if (ret != 0) {
        FILE *err_fp = fopen(files.stderr_path, "r");
        if (err_fp) {
            char error_msg[BUFFER_SIZE];
            size_t err_len = fread(error_msg, 1, sizeof(error_msg) - 1, err_fp);
            if (err_len > 0) {
                error_msg[err_len] = '\0';
                mysyslog(error_msg, WARN, 0, 0, LOG_FILE);
            }
            fclose(err_fp);
        }
    }
    
    cleanup_temp_files(&files);
    return 0;
}

int main() {
    daemonize();
    
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_signal;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sa.sa_handler = SIG_IGN;
    sigaction(SIGHUP, &sa, NULL);

    Config config = parse_config(MAIN_CONFIG);
    if (config.port <= 0 || config.port > 65535) {
        mysyslog("Invalid port", ERROR, 0, 0, LOG_FILE);
        remove_pidfile();
        return 1;
    }
    
    int sock_type;
    if (strcmp(config.socket_type, "stream") == 0) {
        sock_type = SOCK_STREAM;
    } else {
        sock_type = SOCK_DGRAM;
    }
    
    int sockfd = socket(AF_INET, sock_type, 0);
    if (sockfd < 0) {
        mysyslog("Socket creation failed", ERROR, 0, 0, LOG_FILE);
        remove_pidfile();
        return 1;
    }
    
    int opt = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        mysyslog("setsockopt failed", ERROR, 0, 0, LOG_FILE);
        close(sockfd);
        remove_pidfile();
        return 1;
    }
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(config.port);
    addr.sin_addr.s_addr = INADDR_ANY;
    
    if (bind(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        mysyslog("Bind failed", ERROR, 0, 0, LOG_FILE);
        close(sockfd);
        remove_pidfile();
        return 1;
    }
    
    if (sock_type == SOCK_STREAM) {
        if (listen(sockfd, 5) < 0) {
            mysyslog("Listen failed", ERROR, 0, 0, LOG_FILE);
            close(sockfd);
            remove_pidfile();
            return 1;
        }
        mysyslog("TCP server started", INFO, 0, 0, LOG_FILE);
    } else {
        mysyslog("UDP server started", INFO, 0, 0, LOG_FILE);
    }
    
    while (!stop) {
        struct sockaddr_in cli_addr;
        socklen_t addr_len = sizeof(cli_addr);
        char buffer[BUFFER_SIZE];
        int connfd = sockfd;
        
        if (sock_type == SOCK_STREAM) {
            connfd = accept(sockfd, (struct sockaddr*)&cli_addr, &addr_len);
            if (connfd < 0) {
                if (errno == EINTR) {
                    continue;
                }
                mysyslog("Accept failed", ERROR, 0, 0, LOG_FILE);
                continue;
            }
        }
        
        ssize_t n;
        if (sock_type == SOCK_STREAM) {
            n = recv(connfd, buffer, BUFFER_SIZE - 1, 0);
        } else {
            n = recvfrom(connfd, buffer, BUFFER_SIZE - 1, 0,
                   (struct sockaddr*)&cli_addr, &addr_len);
        }
        
        if (n <= 0) {
            if (sock_type == SOCK_STREAM) {
                close(connfd);
            }
            continue;
        }
        buffer[n] = '\0';
        
        char *username = strtok(buffer, ":");
        char *command = strtok(NULL, "");
        
        if (!username || !command) {
            mysyslog("Invalid request format", WARN, 0, 0, LOG_FILE);
            if (sock_type == SOCK_STREAM) {
                close(connfd);
            }
            continue;
        }
        
        char response[BUFFER_SIZE] = {0};
        if (user_allowed(username)) {
            if (execute_command(command, response, sizeof(response))) {
                strcpy(response, "Command execution failed");
            }
        } else {
            snprintf(response, sizeof(response), "Access denied for %s", username);
            mysyslog("User not allowed", WARN, 0, 0, LOG_FILE);
        }
        
        if (sock_type == SOCK_STREAM) {
            if (send(connfd, response, strlen(response), 0) < 0) {
                mysyslog("Send failed", ERROR, 0, 0, LOG_FILE);
            }
            close(connfd);
        } else {
            if (sendto(sockfd, response, strlen(response), 0,
                     (struct sockaddr*)&cli_addr, addr_len) < 0) {
                mysyslog("Sendto failed", ERROR, 0, 0, LOG_FILE);
            }
        }
    }
    
    close(sockfd);
    remove_pidfile();
    mysyslog("Server stopped", INFO, 0, 0, LOG_FILE);
    return 0;
}
