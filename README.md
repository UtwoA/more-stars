# More Stars

Сервис для продажи **Telegram Stars** и цифровых подарков через **Telegram Mini App**.
Проект включает backend на FastAPI, фронтенд Mini App, интеграции с платежами, бонусами и админ-инструментами.

## О проекте
`more-stars` решает полный цикл покупки внутри Telegram:
- пользователь выбирает Stars или подарок;
- оплачивает удобным способом;
- заказ подтверждается автоматически;
- выполняется доставка (Fragment / Gift API) с ретраями;
- администратор получает аудит и отчёты.

## Ключевые возможности
- продажа `Stars` с тарифными уровнями по объёму;
- продажа `Telegram Gifts` из управляемого каталога;
- оплаты: `Crypto Pay`, `Platega (SBP/Card)`, `TonConnect`;
- `Robokassa` присутствует в коде, но сейчас временно отключена (`503`);
- промокоды, резервирование и погашение после успешной оплаты;
- бонусные начисления и реферальная программа;
- админ-панель с OTP-авторизацией, аналитикой и управлением настройками;
- фоновые задачи: синхронизация неоплаченных/зависших заказов, ретраи подарков, daily report, мониторинг доступности Mini App.

## Архитектура
```text
Telegram Mini App (frontend/) 
        |
        v
FastAPI backend (backend/app)
  |- Public API      (/settings, /promo, /gifts, /profile, /raffle)
  |- Orders API      (/orders/*)
  |- Webhooks API    (/webhook/*)
  |- Admin API       (/admin/* + /admin/panel)
  |
  +--> PostgreSQL (orders/users/promos/bonuses/audit)
  +--> Payment providers (Crypto Pay / Platega / TonCenter)
  +--> Delivery providers (Fragment for Stars, Pyrofork for Gifts)
  +--> Telegram Bot notifications (users/admins)
```

## Структура репозитория
- `backend/` — серверное приложение FastAPI, модели, API, интеграции, фоновые процессы.
- `frontend/` — Telegram Mini App и статические страницы (`index.html`, `success.html`, `failure.html` и др.).
- `docker-compose.yml` — локальный запуск PostgreSQL + backend.
- `.env.example` — пример всех переменных окружения.

## Поддерживаемые платежные сценарии
1. `POST /orders/crypto`
Создаёт заказ, считает сумму в crypto и возвращает инвойс Crypto Pay.

2. `POST /orders/platega`
Создаёт заказ и возвращает `redirect` для оплаты через Platega.

3. `POST /orders/tonconnect`
Создаёт заказ с уникальной TON-суммой для последующего матчинга транзакции.

4. `POST /orders/stars`
Создаёт инвойс Telegram Stars (для сценариев оплаты в звёздах).

5. Подтверждение/синхронизация статуса
- вебхуки: `/webhook/crypto`, `/webhook/platega/{token}`, `/webhook/robokassa`;
- fallback-синхронизация фоновыми джобами, если вебхук задержался/не пришёл.

## Безопасность
- защита `orders/*` через `x-telegram-init-data` (или `x-api-key` для доверенного канала);
- rate limit на создание/обработку заказов (`RATE_LIMIT_PER_MIN`);
- проверка подписи вебхуков провайдеров;
- админ-доступ через OTP и cookie-сессию;
- сравнение ключей через constant-time функции.

## Требования
- Docker + Docker Compose (рекомендуемый путь);
- либо Python 3.11+ и PostgreSQL 15+ для локального запуска без контейнеров.

## Быстрый старт (Docker)
1. Подготовьте переменные:
```bash
cp .env.example .env
```

2. Минимально заполните в `.env`:
- `BOT_TOKEN`
- `API_AUTH_KEY`
- PostgreSQL переменные (`POSTGRES_*`)
- ключи выбранного платежного провайдера (`CRYPTOBOT_TOKEN` или `PLATEGA_*` и т.д.)
- `MINI_APP_URL`

3. Запустите сервисы:
```bash
docker compose up -d --build
```

4. Проверьте запуск:
- backend: `http://localhost:8000`
- admin panel: `http://localhost:8000/admin/panel`

## Локальный запуск без Docker
```bash
cd backend
pip install -r requirements.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

Важно: backend ожидает доступную PostgreSQL и корректный `.env` в корне репозитория.

## Переменные окружения
Полный список см. в `.env.example`.

Критичные группы:
- Telegram/бот: `BOT_TOKEN`, `MINI_APP_URL`
- авторизация API: `API_AUTH_KEY`, `ALLOW_UNVERIFIED_INITDATA`
- БД: `POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_DB`, `POSTGRES_HOST`, `POSTGRES_PORT`
- платежи: `CRYPTOBOT_TOKEN`, `PLATEGA_*`, `TONCONNECT_WALLET_ADDRESS`, `TONCENTER_*`
- бизнес-настройки: `REFERRAL_PERCENT`, `STAR_COST_USD_PER_100`, `STAR_COST_RATE_SOURCE`, `BONUS_MIN_STARS`
- админ/отчёты: `ADMIN_CHAT_ID`, `ADMIN_REPORT_TIME`, `ADMIN_OTP_*`
- доставка Gifts через MTProto: `PYROFORK_*`

## Основные API-группы
Public:
- `GET /settings/public`
- `GET /gifts`
- `GET /promo/validate`, `POST /promo/apply`
- `GET /profile/summary`
- `GET /raffle/summary`

Orders:
- `POST /orders/crypto`
- `POST /orders/platega`
- `POST /orders/tonconnect`
- `POST /orders/stars`
- `POST /orders/gift/recipient`
- `POST /orders/stars/confirm`
- `GET /orders/last`, `GET /orders/history`, `GET /orders/{order_id}`

Admin:
- `POST /admin/otp/request`, `POST /admin/otp/verify`
- `GET/POST /admin/settings`
- `POST /admin/promo/create`
- `POST /admin/bonus/*`
- `GET/POST /admin/gifts`
- `GET /admin/analytics*`, `GET /admin/audit*`
- `POST /admin/raffle/*`

## Администрирование
- web-интерфейс: `/admin/panel`
- поддерживаются настройки цен, баннера, промо-текста, параметров розыгрышей;
- есть массовая выдача бонусов и генерация бонус-claim ссылок;
- собирается операционный аудит по оплатам и доставке.

## Фоновые процессы при старте backend
На `startup` автоматически запускаются:
- инициализация/создание схемы БД;
- ежедневные отчёты администраторам;
- проверка доступности `MINI_APP_URL`;
- sync статусов платежей и догрузка зависших заказов;
- цикл ретрая неотправленных подарков;
- polling админ-бота.

## Тесты
```bash
cd backend
pytest
```

## Эксплуатационные заметки
- для Production рекомендуется проксировать backend через Nginx/Caddy;
- `frontend/` обычно разворачивается как статический сайт (домен из `MINI_APP_URL`);
- в проде обязательно задайте уникальные секреты и выключите `ALLOW_UNVERIFIED_INITDATA`;
- перед релизом проверьте webhook-секреты и allowlist IP для платежных провайдеров.

## Статус проекта
Репозиторий активный, сфокусирован на Telegram Mini App e-commerce сценариях (Stars + Gifts).
