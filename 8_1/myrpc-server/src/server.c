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

volatile sig_atomic_t stop;

void handle_signal(int sig) {
    stop = 1;
}

typedef struct {
    char users[MAX_USERS][32];
    int count;
} UserList;

/* Функция для демонизации */
void daemonize() {
    pid_t pid = fork();
    
    if (pid < 0) {
        exit(EXIT_FAILURE);
    }
    
    if (pid > 0) {
        exit(EXIT_SUCCESS);
    }
    
    if (setsid() < 0) {
        exit(EXIT_FAILURE);
    }
    
    signal(SIGCHLD, SIG_IGN);
    signal(SIGHUP, SIG_IGN);
    
    pid = fork();
    
    if (pid < 0) {
        exit(EXIT_FAILURE);
    }
    
    if (pid > 0) {
        exit(EXIT_SUCCESS);
    }
    
    umask(0);
    chdir("/");
    
    for (int x = sysconf(_SC_OPEN_MAX); x >= 0; x--) {
        close(x);
    }
    
    openlog("myrpc", LOG_PID, LOG_DAEMON);
}

/* Функция для записи PID файла */
void write_pidfile() {
    FILE *f = fopen(PID_FILE, "w");
    if (f) {
        fprintf(f, "%d\n", getpid());
        fclose(f);
    }
}

/* Функция для удаления PID файла */
void remove_pidfile() {
    unlink(PID_FILE);
}

int load_users(UserList *list) {
    FILE *file = fopen(USERS_PATH, "r");
    if (!file) {
        syslog(LOG_ERR, "Cannot open users file");
        return 0;
    }

    char line[64];
    list->count = 0;

    while (fgets(line, sizeof(line), file) && list->count < MAX_USERS) {
        line[strcspn(line, "\n")] = 0;
        
        if (line[0] == '#' || line[0] == '\0') {
            continue;
        }

        strncpy(list->users[list->count], line, 31);
        list->users[list->count][31] = '\0';
        list->count++;
    }

    fclose(file);
    return 1;
}

int is_user_allowed(const UserList *list, const char *username) {
    for (int i = 0; i < list->count; i++) {
        if (strcmp(list->users[i], username) == 0) {
            return 1;
        }
    }
    return 0;
}

int create_temp_file(char *template) {
    int fd = mkstemp(template);
    if (fd < 0) {
        syslog(LOG_ERR, "Temp file creation failed");
        return -1;
    }
    close(fd);
    return 0;
}

int execute_and_capture(const char *command, char *output, size_t max_len) {
    char stdout_file[] = TEMPLATE_STDOUT;
    char stderr_file[] = TEMPLATE_STDERR;
    
    if (create_temp_file(stdout_file) != 0 || create_temp_file(stderr_file) != 0) {
        return -1;
    }

    char cmd[BUFFER_SIZE];
    snprintf(cmd, BUFFER_SIZE, "%s >%s 2>%s", command, stdout_file, stderr_file);
    
    int ret = system(cmd);
    if (ret != 0) {
        remove(stdout_file);
        remove(stderr_file);
        return -1;
    }

    FILE *f = fopen(stdout_file, "r");
    if (!f) {
        remove(stdout_file);
        remove(stderr_file);
        return -1;
    }

    size_t read = fread(output, 1, max_len - 1, f);
    output[read] = '\0';
    fclose(f);

    remove(stdout_file);
    remove(stderr_file);

    return 0;
}

int setup_server_socket(int port, int is_stream) {
    int sock_type = is_stream ? SOCK_STREAM : SOCK_DGRAM;
    int sockfd = socket(AF_INET, sock_type, 0);
    
    if (sockfd < 0) {
        syslog(LOG_ERR, "Socket creation failed");
        return -1;
    }

    int opt = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        close(sockfd);
        syslog(LOG_ERR, "setsockopt failed");
        return -1;
    }

    struct sockaddr_in servaddr = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = INADDR_ANY,
        .sin_port = htons(port)
    };

    if (bind(sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr)) < 0) {
        close(sockfd);
        syslog(LOG_ERR, "Bind failed");
        return -1;
    }

    if (is_stream && listen(sockfd, 5) < 0) {
        close(sockfd);
        syslog(LOG_ERR, "Listen failed");
        return -1;
    }

    return sockfd;
}

void process_stream_request(int connfd, const UserList *users) {
    char buffer[BUFFER_SIZE];
    int n = recv(connfd, buffer, BUFFER_SIZE, 0);

    if (n <= 0) return;

    buffer[n] = '\0';
    syslog(LOG_INFO, "Request received");

    char *username = strtok(buffer, ":");
    char *command = strtok(NULL, "\0");
    
    char response[BUFFER_SIZE];
    if (!username || !command) {
        const char *err = "2: Invalid request format";
        send(connfd, err, strlen(err), 0);
        return;
    }

    if (!is_user_allowed(users, username)) {
        snprintf(response, BUFFER_SIZE, "1: Access denied for '%s'", username);
        syslog(LOG_WARNING, "Access denied for %s", username);
    } else {
        if (execute_and_capture(command, response, BUFFER_SIZE) != 0) {
            strcpy(response, "3: Command execution failed");
            syslog(LOG_ERR, "Command failed");
        } else {
            syslog(LOG_INFO, "Command executed");
        }
    }

    send(connfd, response, strlen(response), 0);
}

void process_datagram_request(int sockfd, const UserList *users) {
    struct sockaddr_in cliaddr;
    socklen_t len = sizeof(cliaddr);
    char buffer[BUFFER_SIZE];
    
    int n = recvfrom(sockfd, buffer, BUFFER_SIZE, 0, (struct sockaddr*)&cliaddr, &len);
    if (n <= 0) return;

    buffer[n] = '\0';
    syslog(LOG_INFO, "Request received");

    char *username = strtok(buffer, ":");
    char *command = strtok(NULL, "\0");
    
    char response[BUFFER_SIZE];
    if (!username || !command) {
        const char *err = "2: Invalid request format";
        sendto(sockfd, err, strlen(err), 0, (struct sockaddr*)&cliaddr, len);
        return;
    }

    if (!is_user_allowed(users, username)) {
        snprintf(response, BUFFER_SIZE, "1: Access denied for '%s'", username);
        syslog(LOG_WARNING, "Access denied for %s", username);
    } else {
        if (execute_and_capture(command, response, BUFFER_SIZE) != 0) {
            strcpy(response, "3: Command execution failed");
            syslog(LOG_ERR, "Command failed");
        } else {
            syslog(LOG_INFO, "Command executed");
        }
    }

    sendto(sockfd, response, strlen(response), 0, (struct sockaddr*)&cliaddr, len);
}

int main(int argc, char *argv[]) {
    int foreground = 0;
    
    /* Проверка аргументов командной строки */
    if (argc > 1 && strcmp(argv[1], "-f") == 0) {
        foreground = 1;
    }

    /* Демонизация */
    if (!foreground) {
        daemonize();
    }

    /* Настройка обработчиков сигналов */
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    signal(SIGQUIT, handle_signal);

    /* Запись PID файла */
    write_pidfile();

    /* Инициализация конфигурации */
    Config config = parse_config(CONFIG_PATH);
    if (config.port == 0) {
        syslog(LOG_ERR, "Invalid configuration");
        remove_pidfile();
        return 1;
    }

    UserList users;
    if (!load_users(&users)) {
        remove_pidfile();
        return 1;
    }

    /* Настройка сокета */
    int is_stream = strcmp(config.socket_type, "stream") == 0;
    int sockfd = setup_server_socket(config.port, is_stream);
    if (sockfd < 0) {
        remove_pidfile();
        return 1;
    }

    syslog(LOG_INFO, "%s server started on port %d", 
           is_stream ? "Stream" : "Datagram", config.port);

    /* Основной цикл обработки запросов */
    while (!stop) {
        if (is_stream) {
            struct sockaddr_in cliaddr;
            socklen_t len = sizeof(cliaddr);
            int connfd = accept(sockfd, (struct sockaddr*)&cliaddr, &len);
            
            if (connfd < 0) continue;
            
            process_stream_request(connfd, &users);
            close(connfd);
        } else {
            process_datagram_request(sockfd, &users);
        }
    }

    /* Завершение работы */
    close(sockfd);
    remove_pidfile();
    syslog(LOG_INFO, "Server stopped");
    closelog();

    return 0;
}
