# Инструкция по миграции БД для VPN Statistics

## Описание изменений

Добавлено новое поле `public_key_client` для хранения публичного ключа **клиента** (вычисленного из `PrivateKey`).

### Два типа публичных ключей:
- **`public_key`** — публичный ключ **сервера** (из `[Peer]` в конфиге клиента) — используется для восстановления конфигов
- **`public_key_client`** — публичный ключ **клиента** (вычисленный из `PrivateKey` в `[Interface]`) — используется для сопоставления со статистикой из `wg show dump`

## Шаги миграции

### 1. Выполните SQL миграцию

```bash
sudo -u postgres psql -d services -f migration_add_public_key_client.sql
```

Или вручную:

```sql
ALTER TABLE vpnusers 
ADD COLUMN IF NOT EXISTS public_key_client TEXT;

COMMENT ON COLUMN vpnusers.public_key IS 'Зашифрованный публичный ключ СЕРВЕРА (из [Peer] в конфиге клиента)';
COMMENT ON COLUMN vpnusers.public_key_client IS 'Зашифрованный публичный ключ КЛИЕНТА (вычисленный из PrivateKey)';

CREATE INDEX IF NOT EXISTS idx_vpnusers_address_provider_interface 
ON vpnusers(address, provider1, interface) 
WHERE public_key_client IS NOT NULL;
```

### 2. Запустите скрипт

При первом запуске после миграции скрипт автоматически:
- Найдёт все записи без `public_key_client`
- Вычислит публичные ключи клиентов из их приватных ключей
- Зашифрует и сохранит их в БД

```bash
sudo python3 /opt/backups/scripts/vpn_statistic.py
```

### 3. Проверьте результат

В логе должны появиться строки:
```
🔧 Обновление публичных ключей клиентов для N существующих записей...
    🔑 Обновлен public_key_client для КОД_КЛИЕНТА
```

И затем успешное сопоставление:
```
✅ КОД_КЛИЕНТА (IP_АДРЕС) — 🟢 активен, RX: ..., TX: ...
✅ Обновлено N записей статистики VPN
```

## Новая логика сопоставления

### Было (неправильно):
1. Брали `PublicKey` из секции `[Peer]` конфига клиента (это ключ сервера!)
2. Пытались сопоставить с `wg show dump` (там ключи клиентов)
3. ❌ Совпадений не было

### Стало (правильно):
1. Берём IP из `allowed_ips` в `wg show dump`
2. Находим всех клиентов с таким IP на данном провайдере/интерфейсе
3. Для каждого кандидата расшифровываем `public_key_client`
4. Сравниваем с публичным ключом из `wg show dump`
5. ✅ При совпадении обновляем статистику

## Откат миграции (если нужно)

```sql
ALTER TABLE vpnusers DROP COLUMN IF EXISTS public_key_client;
DROP INDEX IF EXISTS idx_vpnusers_address_provider_interface;
```

**Внимание!** После отката старая версия скрипта не будет работать правильно.

