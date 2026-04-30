# wgvpn

Telegram-бот для управления WireGuard VPN на Ubuntu-сервере.

## Возможности

- Добавление пользователей: генерация ключей, назначение IP, готовый конфиг-файл для устройства
- Удаление пользователей
- Список всех пользователей с IP, хэндшейком и трафиком (если интерфейс активен)
- Получение конфига для существующего пользователя
- Запуск / остановка WireGuard, просмотр статуса
- Горячее применение изменений через `wg syncconf` — без перезапуска сервиса
- При старте бота `wg0.conf` автоматически синхронизируется с базой пользователей
- Интерактивный диалог: команды без аргументов спрашивают логин отдельным сообщением

## Требования

- Ubuntu (или любой Linux с systemd и wireguard-tools)
- `wg` и `wg-quick` в PATH
- Telegram Bot Token ([получить у @BotFather](https://t.me/BotFather))

## Сборка

```bash
# Кросс-компиляция под Linux amd64 (запускать с Windows или Mac)
make build

# Или напрямую
GOOS=linux GOARCH=amd64 go build -ldflags "-s -w" -o wgvpn ./cmd/wgvpn/
```

## Установка на сервер

Скопируй бинарник и systemd unit на сервер любым удобным способом, затем выполни:

```bash
# Разместить бинарник
cp wgvpn /usr/local/bin/wgvpn
chmod +x /usr/local/bin/wgvpn

# Создать директорию конфигурации
mkdir -p /etc/wgvpn

# Скопировать пример конфига и заполнить его
cp config.example.json /etc/wgvpn/config.json
nano /etc/wgvpn/config.json   # вписать telegram_token и admin_ids

# Если переносишь существующих пользователей:
cp users.json /etc/wgvpn/users.json

# Установить и запустить службу
cp wgvpn.service /etc/systemd/system/wgvpn.service
systemctl daemon-reload
systemctl enable --now wgvpn
```

## Конфигурация

Файл `/etc/wgvpn/config.json`:

```json
{
  "telegram_token": "1234567890:AAxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
  "admin_ids": [123456789],
  "wg_config_path": "/etc/wireguard/wg0.conf",
  "wg_interface": "wg0",
  "server_endpoint": "1.2.3.4:51820",
  "server_public_key": "BASE64_SERVER_PUBLIC_KEY_HERE",
  "subnet": "10.8.0.0/24",
  "server_ip": "10.8.0.1",
  "dns": "8.8.8.8",
  "client_allowed_ips": "0.0.0.0/0, ::/0",
  "users_file": "/etc/wgvpn/users.json"
}
```

| Поле | Описание |
|---|---|
| `telegram_token` | Токен бота от @BotFather |
| `admin_ids` | Список Telegram user ID, которым разрешён доступ |
| `wg_config_path` | Путь к конфигу WireGuard (обычно `/etc/wireguard/wg0.conf`) |
| `wg_interface` | Имя интерфейса WireGuard (`wg0`) |
| `server_endpoint` | Публичный адрес и порт сервера (`ip:port`) |
| `server_public_key` | Публичный ключ сервера (из `[Interface]` секции wg0.conf) |
| `subnet` | Подсеть VPN в CIDR-нотации |
| `server_ip` | IP сервера внутри VPN (резервируется, не выдаётся клиентам) |
| `dns` | DNS для клиентских конфигов |
| `client_allowed_ips` | AllowedIPs в клиентском конфиге (`0.0.0.0/0, ::/0` — весь трафик через VPN) |
| `users_file` | Путь к базе пользователей (JSON) |

## Команды бота

| Команда | Описание |
|---|---|
| `/adduser [login]` | Добавить пользователя, получить конфиг-файл |
| `/deluser [login]` | Удалить пользователя |
| `/listusers` | Список всех пользователей с IP и статистикой |
| `/getconfig [login]` | Повторно отправить конфиг-файл пользователя |
| `/wgstate` | Показать, запущен ли WireGuard |
| `/startwg` | Запустить службу WireGuard |
| `/stopwg` | Остановить службу WireGuard |
| `/status` | Вывод `wg show` |
| `/cancel` | Отменить текущий ввод |

Команды с `[login]` работают двумя способами: `/adduser alice` одной строкой или `/adduser` — тогда бот попросит ввести логин отдельным сообщением.


## Как работает синхронизация конфига

При старте и после каждого изменения пользователей:

1. `[Interface]`-секция из `wg0.conf` сохраняется без изменений
2. Все `[Peer]`-блоки перестраиваются из базы пользователей
3. Если WireGuard запущен — изменения применяются горячо через `wg syncconf` (без разрыва соединений)
