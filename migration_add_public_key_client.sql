-- Миграция: добавление поля public_key_client для хранения публичного ключа клиента
-- Дата: 2025-10-16
-- Описание: public_key хранит ключ СЕРВЕРА (для восстановления конфигов),
--           public_key_client хранит ключ КЛИЕНТА (для сопоставления со статистикой)

ALTER TABLE vpnusers 
ADD COLUMN IF NOT EXISTS public_key_client TEXT;

COMMENT ON COLUMN vpnusers.public_key IS 'Зашифрованный публичный ключ СЕРВЕРА (из [Peer] в конфиге клиента)';
COMMENT ON COLUMN vpnusers.public_key_client IS 'Зашифрованный публичный ключ КЛИЕНТА (вычисленный из PrivateKey)';

-- Создаём индекс для ускорения поиска по IP + провайдер + интерфейс
CREATE INDEX IF NOT EXISTS idx_vpnusers_address_provider_interface 
ON vpnusers(address, provider1, interface) 
WHERE public_key_client IS NOT NULL;

