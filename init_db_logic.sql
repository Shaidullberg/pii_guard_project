-- 1. Схема безопасности
CREATE SCHEMA IF NOT EXISTS pii_guard;

-- 2. Таблица аудита (Журнал событий ядра)
CREATE TABLE IF NOT EXISTS pii_guard.audit_log (
    event_id SERIAL PRIMARY KEY,
    event_time TIMESTAMP DEFAULT NOW(),
    db_user TEXT DEFAULT current_user,
    table_name TEXT,
    operation TEXT,
    old_data TEXT,
    new_data TEXT
);

-- Индексы для быстрого поиска по журналу аудита
CREATE INDEX IF NOT EXISTS idx_audit_table ON pii_guard.audit_log(table_name);
CREATE INDEX IF NOT EXISTS idx_audit_time  ON pii_guard.audit_log(event_time DESC);
CREATE INDEX IF NOT EXISTS idx_audit_op    ON pii_guard.audit_log(operation);

-- 3. Функция-шпион (Триггер)
CREATE OR REPLACE FUNCTION pii_guard.log_changes()
RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO pii_guard.audit_log (table_name, operation, old_data, new_data)
    VALUES (
        TG_TABLE_NAME, 
        TG_OP, 
        ROW(OLD.*)::TEXT, -- Сохраняем старую строку
        ROW(NEW.*)::TEXT  -- Сохраняем новую строку
    );
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- 4. Процедура: Включить слежку на таблице
CREATE OR REPLACE PROCEDURE pii_guard.enable_audit(target_table TEXT)
LANGUAGE plpgsql AS $$
BEGIN
    -- Удаляем старый триггер, чтобы не дублировать
    EXECUTE format('DROP TRIGGER IF EXISTS trg_audit_changes ON %I', target_table);
    -- Создаем новый
    EXECUTE format('
        CREATE TRIGGER trg_audit_changes
        AFTER UPDATE OR DELETE ON %I
        FOR EACH ROW
        EXECUTE FUNCTION pii_guard.log_changes()', 
        target_table
    );
END;
$$;

-- 5. Процедура: Быстрое маскирование (SQL-way)
CREATE OR REPLACE PROCEDURE pii_guard.fast_mask(t_name TEXT, c_name TEXT)
LANGUAGE plpgsql AS $$
BEGIN
    -- Мгновенный UPDATE без передачи данных по сети
    EXECUTE format('UPDATE %I SET %I = ''****'' WHERE %I IS NOT NULL', t_name, c_name, c_name);
    
    -- Пишем в лог, что было массовое стирание
    INSERT INTO pii_guard.audit_log (table_name, operation, new_data)
    VALUES (t_name, 'MASS_MASKING', 'Column ' || c_name || ' masked with stars');
END;
$$;