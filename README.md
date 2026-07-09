# Sigmacta — Backend

Бэкенд социальной сети **Sigmacta**: REST API + realtime-чат для мобильного приложения на Flutter.

> 📱 Мобильный клиент: [sigma-social-app](https://github.com/dzhakhann/sigma-social-app)

---

## 🛠 Стек

- **Node.js + Express** (ESM)
- **Supabase** — PostgreSQL + Storage
- **Socket.IO** — сообщения в реальном времени
- **JWT** (HS256) — авторизация · **bcrypt** — хеширование паролей
- **express-rate-limit** — защита от перебора · **zod** — валидация
- **Google Gemini** — ИИ-коуч и рекомендации

---

## 🔐 Безопасность

- Пароли хранятся только как **bcrypt-хеши** (с миграцией легаси-паролей).
- Все изменяющие эндпоинты защищены **JWT** (`authRequired`), приватные данные проверяются по `userId`.
- **Rate-limiting**, ограничение размера загрузок, CORS из переменных окружения.
- `service_role`-ключ Supabase живёт только на сервере и никогда не уходит клиенту.
- Восстановление аккаунта — по **seed-фразе** (в стиле крипто-кошельков).

---

## 📡 Основные группы API

| Область | Эндпоинты (примеры) |
|--------|----------------------|
| Авторизация | `POST /api/register`, `POST /api/login`, `POST /api/recover` |
| Профиль | `GET /api/users/:id`, `PUT /api/users/:id`, `POST /api/follow` |
| Лента и посты | `GET /api/posts`, `GET /api/posts/following`, `POST /api/posts`, `POST /api/posts/:id/repost` |
| Комментарии/лайки | `GET/POST /api/posts/:id/comments`, `POST /api/posts/:id/like` |
| Сторис | `GET /api/stories`, `POST /api/stories` |
| Уведомления | `GET /api/notifications`, `POST /api/notifications/:id/read` |
| Чат (Socket.IO) | `GET /api/chats`, `GET /api/messages/:chatId` + realtime-сокеты |
| Цели / Wrapped | `GET/POST /api/goals`, `GET /api/goals/wrapped` |
| ИИ | `POST /api/ai/chat`, `POST /api/ai/recommend` |

---

## 🚀 Запуск

```bash
npm install
npm start        # node server.js
```

### Переменные окружения (`.env`)

```
SUPABASE_URL=...
SUPABASE_SERVICE_ROLE_KEY=...
JWT_SECRET=...
GEMINI_API_KEY=...
GIPHY_API_KEY=...
ALLOWED_ORIGINS=...
```

> `.env` в репозиторий не коммитится (см. `.gitignore`). Секреты хранятся в переменных окружения хостинга.

Деплой: **Render** (auto-deploy при пуше в `main`).

---

## 👤 Автор

**Jaxangir** — архитектура, API, база данных, интеграции.
