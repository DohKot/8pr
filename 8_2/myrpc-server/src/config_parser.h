#ifndef CONFIG_PARSER_H
#define CONFIG_PARSER_H

#define MAX_STRING_LEN 32

typedef struct {
    int port;
    char socket_type[MAX_STRING_LEN];
    char user[MAX_STRING_LEN];  // Добавлено поле для пользователя
} Config;

Config parse_config(const char *filename);

#endif // CONFIG_PARSER_H
