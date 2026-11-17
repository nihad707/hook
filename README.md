# HOOK Cloud 5.0 — модульная версия

```
hook_cloud/
├── main.py                      # фабрика приложения, middleware, lifespan
├── core/
│   ├── config.py                # ВСЕ переменные окружения (БД, Redis, лимиты, секреты)
│   ├── database.py              # SQLAlchemy: engine, SessionLocal, Base (схему создаёт только Alembic)
│   ├── redis_client.py          # ленивый клиент + circuit breaker (падение Redis не тормозит ловушку)
│   ├── security.py              # scrypt, токены Control Center
│   ├── ratelimit.py             # счётчики брутфорса логина (Redis → память)
│   ├── keys.py                  # генерация/хэш API-ключей, общий кэш ключей в Redis
│   └── utils.py
├── models/
│   ├── db.py                    # UserDB, ProjectDB, ProjectKeyDB, SandboxSessionDB
│   └── schemas.py               # Pydantic-схемы с max_length
├── engine/
│   ├── persona.py               # фейковые компании/серверы/креды (детерминированы по seed)
│   ├── vectors.py               # 15 векторов обмана (.env, SQL-дампы, Docker/K8s API, логин-приманка…)
│   ├── routing.py               # классификация атакующего + выбор вектора
│   ├── deception.py             # deceive(), compute_delay(); жёсткий запрет на 403/429
│   ├── state.py                 # распределённое состояние: Redis (Lua) + fallback в память
│   └── events.py                # write-behind запись сессий в БД
├── routers/  auth.py · projects.py · trap.py · views.py · deps.py
├── templates/ landing.html · admin.html      # ← создаются скриптом scripts/extract_assets.py
├── static/    logo.png · favicon.png         # ← создаются скриптом scripts/extract_assets.py
├── migrations/ (Alembic)  0001_initial · 0002_unique_session_per_ip
├── tests/test_engine.py
├── Dockerfile · docker-compose.yml · railway.json · .env.example · requirements.txt
```

## 0. Один раз: вытащить лендинг, админку и логотипы из старого main.py
```bash
python scripts/extract_assets.py /путь/к/старому/main.py
```

## 1. Запуск одной командой
```bash
cp .env.example .env          # впишите HOOK_SECRET_KEY:  python -c "import secrets; print(secrets.token_hex(32))"
docker compose up --build     # postgres + redis + migrate (alembic upgrade head) + app
# → http://localhost:8080   (лендинг),  /admin  (Control Center),  /docs
```

## 2. Миграции (Alembic)
```bash
alembic upgrade head                              # новая БД
alembic revision --autogenerate -m "add column"   # после изменения models/db.py
alembic stamp 0001 && alembic upgrade head        # УЖЕ существующая БД от монолита v4.0
alembic downgrade -1
```
`0001` в точности повторяет схему v4.0, поэтому существующую базу достаточно «проштамповать». `0002` удаляет
дубли сессий и ставит уникальный индекс `(project_id, attacker_ip)` — он нужен, когда несколько воркеров
пишут одного и того же атакующего одновременно.

## 3. Railway
1. New Project → Deploy from GitHub (Dockerfile подхватится, `railway.json` уже настроен).
2. Add → Database → **PostgreSQL** и **Redis**.
3. Variables сервиса:
   `DATABASE_URL=${{Postgres.DATABASE_URL}}`, `REDIS_URL=${{Redis.REDIS_URL}}`,
   `HOOK_SECRET_KEY=<64 hex>` (одинаковый на всех репликах), при желании `WEB_CONCURRENCY=4`.
4. Миграции выполняет `preDeployCommand` (`alembic upgrade head`) перед каждым деплоем; healthcheck — `/healthz`.

## Как устроено горизонтальное масштабирование
* Состояние атакующего (stage, tarpit, счётчики логин-приманки) — Redis HASH + ZSET окна флуда.
  `touch()` — один атомарный Lua-вызов на запрос, время берётся из Redis `TIME` (без рассинхрона часов реплик).
* Персона выводится из `хэша` seed = sha256(HOOK_SECRET_KEY | project | ip): любой воркер отвечает
  атакующему «тем же» вымышленным сервером. Поэтому `HOOK_SECRET_KEY` обязан быть одинаковым везде.
* Нет Redis / он упал → автоматически process-local память (ретрай через 10 с). Ловушка не ждёт мёртвый Redis
  (таймаут 250 мс + circuit breaker). Без Redis запускайте ровно один воркер.
* Кэш API-ключей общий (Redis); ротация/удаление ключа (`POST /v1/projects/{id}/rotate-key`,
  `DELETE /v1/projects/{id}`) действует на всех репликах мгновенно.

## Политика «никаких 403/429 для атакующих»
* `deceive()` физически не пропускает 403/429 (защитный `FORBIDDEN_STATUSES`).
* Флуд → растёт `tarpit`-уровень → растёт задержка (`X-Hook-Delay-Ms`, до `HOOK_TARPIT_MAX_MS`) и размер/запутанность
  ответов (бесконечная пагинация, job-polling, большие дампы). HTTP-код для атакующего остаётся 200 (или 401 в логин-приманке).
* Поля запроса обрезаются (а не отклоняются), поэтому мусорный ввод не может вызвать 422 на ловушке.
* 429 остаётся только на **вашем** `/v1/auth/login` и `/v1/auth/register` (защита Control Center), 403 — только при неверном HOOK API-ключе SDK.

## Тесты
```bash
python -m unittest discover -t . -s tests -v     # движок, без FastAPI/Redis/БД
```
