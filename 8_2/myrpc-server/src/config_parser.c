#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include "config_parser.h"

static void trim_whitespace(char *str) {
    if (str == NULL) return;
    
    char *start = str;
    while (*start && (*start == ' ' || *start == '\t')) {
        start++;
    }
    
    char *end = start + strlen(start) - 1;
    while (end > start && (*end == ' ' || *end == '\t' || *end == '\n' || *end == '\r')) {
        *end-- = '\0';
    }
    
    if (start != str) {
        memmove(str, start, end - start + 2);
    }
}

Config parse_config(const char *filename) {
    Config config = {
        .port = 0,
        .socket_type = "stream",
        .user = "root"  // Значение по умолчанию
    };

    if (filename == NULL) {
        return config;
    }

    FILE *file = fopen(filename, "r");
    if (!file) {
        return config;
    }

    char line[256];
    while (fgets(line, sizeof(line), file)) {
        line[strcspn(line, "\r\n")] = '\0';
        trim_whitespace(line);

        if (line[0] == '#' || line[0] == '\0') {
            continue;
        }

        char *key = strtok(line, "=");
        char *value = strtok(NULL, "");

        if (key == NULL || value == NULL) {
            continue;
        }

        trim_whitespace(key);
        trim_whitespace(value);

        if (strcmp(key, "port") == 0) {
            config.port = atoi(value);
        } 
        else if (strcmp(key, "socket_type") == 0) {
            strncpy(config.socket_type, value, MAX_STRING_LEN - 1);
            config.socket_type[MAX_STRING_LEN - 1] = '\0';
        }
        else if (strcmp(key, "user") == 0) {
            strncpy(config.user, value, MAX_STRING_LEN - 1);
            config.user[MAX_STRING_LEN - 1] = '\0';
        }
    }

    fclose(file);
    return config;
}
