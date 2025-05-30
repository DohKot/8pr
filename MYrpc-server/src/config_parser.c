#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include "config_parser.h"

static void trim_whitespace(char *str) {
    if (!str) return;

    // Удаление начальных пробелов
    char *start = str;
    while (*start && (*start == ' ' || *start == '\t')) start++;

    // Удаление конечных пробелов
    char *end = start + strlen(start) - 1;
    while (end > start && (*end == ' ' || *end == '\t' || *end == '\n' || *end == '\r')) 
        *end-- = '\0';

    if (start != str) 
        memmove(str, start, end - start + 2);

    // Очистка пробелов вокруг запятых
    char *comma = strchr(str, ',');
    while (comma) {
        if (comma > str && *(comma-1) == ' ')
            memmove(comma-1, comma, strlen(comma)+1);
        if (*(comma+1) == ' ')
            memmove(comma+1, comma+2, strlen(comma+2)+1);
        comma = strchr(comma, ',');
    }
}

Config parse_config(const char *filename) {
    Config config = {
        .port = 0,
        .socket_type = "stream",
        .user = "",
        .users_count = 0
    };
    memset(config.users, 0, sizeof(config.users));

    if (!filename) return config;

    FILE *file = fopen(filename, "r");
    if (!file) return config;

    char line[256];
    while (fgets(line, sizeof(line), file)) {
        line[strcspn(line, "\r\n")] = '\0';
        trim_whitespace(line);

        if (line[0] == '#' || line[0] == '\0') continue;

        char *key = strtok(line, "=");
        char *value = strtok(NULL, "");

        if (!key || !value) continue;

        trim_whitespace(key);
        trim_whitespace(value);

        if (strcmp(key, "port") == 0) {
            config.port = atoi(value);
        }
        else if (strcmp(key, "socket_type") == 0) {
            strncpy(config.socket_type, value, MAX_STRING_LEN-1);
            config.socket_type[MAX_STRING_LEN-1] = '\0';
        }
        else if (strcmp(key, "user") == 0) {
            strncpy(config.user, value, MAX_STRING_LEN-1);
            config.user[MAX_STRING_LEN-1] = '\0';
        }
        else if (strcmp(key, "users") == 0) {
            char *token = strtok(value, ",");
            while (token && config.users_count < MAX_USERS) {
                trim_whitespace(token);
                strncpy(config.users[config.users_count], token, MAX_STRING_LEN-1);
                config.users[config.users_count][MAX_STRING_LEN-1] = '\0';
                config.users_count++;
                token = strtok(NULL, ",");
            }
        }
    }

    fclose(file);
    return config;
}
