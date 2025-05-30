# myRPC
**Система удалённого выполнения команд через сокеты с авторизацией пользователей**

## Описание
Система myRPC состоит из двух основных компонентов:
- `myRPC-client` — консольное приложение для отправки команд
- `myRPC-server` — серверное приложение для выполнения команд

**Ключевые возможности:**
- Поддержка потоковых (TCP) и датаграммных (UDP) соединений
- Авторизация пользователей через конфигурационный файл
- Логирование операций через `libmysyslog`
- Поддержка текстового файла

## Сборка проекта
### Общая сборка
```bash
make all      # Сборка всех компонентов
make clean    # Очистка артефактов
make deb      # дДля генерация deb-пакетов
```

## Сборка клиента
```bash
cd myrpc-client
make          # Компиляция
make deb      # Создание deb-пакета
make clean    # Очистка
```
## Сборка сервера
```bash
cd myrpc-server
make          # Компиляция
make deb      # Создание deb-пакета
make clean    # Очистка
```

## Установка и настройка
### Установка из deb-пакетов
```bash
sudo dpkg -i deb/myrpc-client_1.0-1_amd64.deb
sudo dpkg -i deb/myrpc-server_1.0-1_amd64.deb
sudo dpkg -i deb/libmysyslog_1.0-1_amd64.deb
```
### Настройка сервера
```bash
sudo mkdir -p /etc/myRPC
echo -e "port=8080\nsocket_type=stream" | sudo tee /etc/myRPC/myRPC.conf
```
```bash
echo "your_username" | sudo tee /etc/myRPC/users.conf
```

## Использование
### Запуск сервера
```bash
sudo myrpc-server -c /etc/myRPC/myRPC.conf
```
### Примеры работы с клиентом
```bash
myrpc-client -h 127.0.0.1 -p 8080 -s -c "ls -la"
myrpc-client -h 127.0.0.1 -p 8080 -d -c "ls -la"
```
