# Сборка и развёртывание gate21

Документ описывает сборку бинаря и первоначальную конфигурацию инстанса.

Эксплуатация требует внешней TLS-терминации (напр. nginx). Публиковать HTTP-порт шлюза наружу нельзя: rate limit берёт IP из
заголовка `X-Forwarded-For`, подделываемого до TLS-терминатора.

## Сборка

Требования: Go 1.27.

```bash
CGO_ENABLED=0 go build -trimpath -ldflags="-buildid=" -o gate21 ./src/app/cmd/server
```

Результат — статический бинарь без внешних зависимостей.

### Docker (рекомендуется)

Сборка с Dockerfile:

```bash
docker build -t gate21 .
```

## Конфигурация

Настройка через переменные окружения. Обязательные: `AUTH_COOKIE_KEY`
(ключ подписи HMAC, ≥16 байт) и `AUTH_PUBLIC_BASE` (для device-потока).

| Переменная | По умолчанию | Назначение |
|---|---|---|
| `AUTH_COOKIE_KEY` | — (обязательная) | ключ HMAC для flow-куки |
| `AUTH_LISTEN_ADDR` | `:8080` | адрес слушателя |
| `AUTH_KEYCLOAK_BASE` | `https://auth.21-school.ru` | базовый URL Keycloak |
| `AUTH_KEYCLOAK_REALM` | `EduPowerKeycloak` | realm |
| `AUTH_CLIENTS_PATH` | `clients.json` | путь к реестру клиентов |
| `AUTH_CODE_TTL` | `120s` | TTL одноразового кода (web-поток) |
| `AUTH_FLOW_MAX_AGE` | `5m` | TTL flow-куки |
| `AUTH_HTTP_TIMEOUT` | `10s` | таймаут запросов к Keycloak |
| `AUTH_COOKIE_SECURE` | `true` | `false` только при отсутствии TLS |
| `AUTH_PUBLIC_BASE` | — (обязательно для device-flow) | публичный https-адрес инстанса |
| `AUTH_DEVICE_TTL` | `5m` | TTL device-сессии |
| `AUTH_POLL_INTERVAL` | `5s` | минимальный интервал поллинга |

Длительности задаются числом с единицей (`300s`, `5m`). Нераспознанное значение
тихо заменяется дефолтом — требуется проверка через `/healthz`.

## Реестр клиентов

За основу берётся `clients.json.example`, секреты генерируются:

```bash
openssl rand -hex 32
```

Файл читается при старте; изменения требуют перезапуска.

```json
{
  "clients": [
    {"id": "svc-a", "redirect_uri": "https://svc-a.example.com/oauth/cb", "secret": "<hex>"},
    {"id": "bot-a", "flow": "device", "secret": "<hex>"}
  ]
}
```

## Запуск

Бинарь запускается как обычный процесс. Пример: собранный Docker-образ с
монтированием реестра и окружением:

```bash
docker run -d --name gate21 -p 127.0.0.1:8080:8080 \
  -v "$PWD/clients.json:/app/clients.json:ro" \
  -e AUTH_COOKIE_KEY="$(openssl rand -hex 32)" \
  -e AUTH_PUBLIC_BASE=https://gate21.dnkrsk.ru \
  gate21
```

За TLS-терминацией слушатель недоступен извне. В контейнере приложение
работает под пользователем `gate21` (uid 10001), без прав root.

## Проверка

```bash
curl -s https://gate21.dnkrsk.ru/healthz     # ok
# web-поток:  /authorize?client_id=svc-a
# device-поток:
curl -s -X POST https://gate21.dnkrsk.ru/oauth/device \
  -d 'client_id=bot-a' -d 'client_secret=<hex>'
```

Если в ответе device-потока `verification_url` собран не на публичном домене —
`AUTH_PUBLIC_BASE` не передан в окружение.
