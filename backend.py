import psycopg2
from psycopg2 import sql, pool # <--- Добавлено для защиты от SQL Injection
import re
import os
import datetime
import subprocess
import sqlite3
import streamlit as st
from faker import Faker
from fpdf import FPDF

# Инициализируем генератор (ru_RU - чтобы создавал российские данные)
fake = Faker('ru_RU')

# Читаем конфигурацию из переменных окружения (Docker-friendly)
DB_CONFIG = {
    "dbname": os.getenv("POSTGRES_DB", "testdb"),
    "user": os.getenv("POSTGRES_USER", "admin"),
    "password": os.getenv("POSTGRES_PASSWORD", "secret_password"),
    "host": os.getenv("DB_HOST", "localhost"),
    "port": os.getenv("DB_PORT", "5432")
}

# --- КОНСТАНТЫ И ПАТТЕРНЫ ---

# 1. СТОП-СЛОВА (Для умного фильтра)
# Если название колонка содержит эти слова, мы считаем её технической и пропускаем (AUTO mode)
SKIP_COLUMN_KEYWORDS = [
    # Технические даты (обычно это метаданные, а не ДР)
    "_at", "_on", "created", "updated", "deleted", "timestamp", "version", 
    "last_login", "expire", "valid_until", "date_joined", "audit",
    # Технические ID (которые выглядят как цифры, но не являются PII)
    "_id", "uuid", "guid", "ref_key", "foreign_key", "order_num", "transaction",
    "invoice", "sku", "ean", "code", "qty", "count"
]

# 2. ПАТТЕРНЫ ПОИСКА (RegEx) - Extended Version
PII_PATTERNS = {
    # --- Базовые контакты ---
    "Email": r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b",
    "Phone (RU)": r"(?:\+7|8|7)[\s\(-]*\d{3}[\s\)-]*\d{3}[\s-]*\d{2}[\s-]*\d{2}",
    
    # --- Личные документы РФ ---
    "Passport (RU Internal)": r"\b\d{4}[\s-]?\d{6}\b",         # Паспорт РФ (серия номер)
    "Passport (RU International)": r"\b\d{2}[\s]?\d{7}\b",      # Загранпаспорт (старый и новый)
    "SNILS": r"\b\d{3}[ -]?\d{3}[ -]?\d{3}[ -]?\d{2}\b",        # СНИЛС
    "Driver License (RU)": r"\b\d{2}[\s]?[A-ZА-Я0-9]{2}[\s]?\d{6}\b", # Водительское удостоверение
    "Birth Certificate (RU)": r"[IVX]{1,3}[\-][А-Я]{2}\s\d{6}", # Свид. о рождении (I-МЯ 123456)
    "OMS (Medical Policy)": r"\b\d{16}\b",                      # Полис ОМС (16 цифр)
    
    # --- Бизнес и Налоги (РФ) ---
    "INN (Individual 12)": r"\b\d{12}\b",                       # ИНН Физлица
    "INN (Company 10)": r"\b\d{10}\b",                          # ИНН Юрлица
    "OGRN (Company)": r"\b\d{13}\b",                            # ОГРН
    "OGRNIP (Entrepreneur)": r"\b\d{15}\b",                     # ОГРНИП
    "KPP (Tax Reason Code)": r"\b\d{9}\b",                      # КПП
    
    # --- Финансы ---
    "Credit Card": r"\b(?:\d{4}[ -]?){3,4}\d{1,4}\b",           # Банковская карта
    "IBAN (Int. Bank Account)": r"\b[A-Z]{2}\d{2}[A-Z0-9]{4,30}\b", # IBAN счет
    "Bitcoin Wallet": r"\b(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}\b", # Криптокошелек BTC
    "Ethereum Wallet": r"\b0x[a-fA-F0-9]{40}\b",                # Криптокошелек ETH
    
    # --- IT и Безопасность ---
    "IPv4 Address": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",             # IP адрес
    "MAC Address": r"\b([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})\b", # MAC адрес устройства
    "JWT Token": r"eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+", # Токены авторизации
    "AWS API Key": r"AKIA[0-9A-Z]{16}",                         # Ключи AWS (утечки облака)
    "Private Key (Header)": r"-----BEGIN (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----", # Приватные ключи
    "UUID / GUID": r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", # Технические ID

    # --- Соцсети и Гео ---
    "Social: Telegram": r"(?:t\.me\/|@)[a-zA-Z0-9_]{5,}",
    "Social: VK": r"(?:vk\.com\/)[a-zA-Z0-9_.]+",
    "Geo Coordinates": r"\b-?\d{1,3}\.\d+,\s*-?\d{1,3}\.\d+\b", # Координаты (широта, долгота)

    # --- Секреты и Пароли ---
    # BCrypt Hash (стандарт для паролей): Начинается на $2a$, $2b$, $2y$ и длинный хвост
    "Password Hash (BCrypt)": r"^\$2[ayb]\$.{56}$",
    
    # MD5 Hash (старый формат паролей): 32 символа hex
    "Password Hash (MD5)": r"\b[a-fA-F0-9]{32}\b",
    
    # SHA-256 Hash: 64 символа hex
    "Password Hash (SHA256)": r"\b[a-fA-F0-9]{64}\b",
    
    # Generic API Key / Secret: требуем смесь верхнего/нижнего регистра + цифру, мин. 32 символа
    # Это снижает ложные срабатывания на обычных словах и UUID-подобных значениях
    "Generic API Key / Secret": r"\b(?=[a-zA-Z0-9]*[A-Z])(?=[a-zA-Z0-9]*[a-z])(?=[a-zA-Z0-9]*[0-9])[a-zA-Z0-9]{32,60}\b",
    
    # --- Сложные проверки (Контекстные) ---
    "FIO (RU)": r"\b[А-ЯЁ][а-яё]{1,20}\s+[А-ЯЁ][а-яё]{1,20}\s+[А-ЯЁ][а-яё]{1,20}\b",
    "Date of Birth": r"\b(?:0[1-9]|[12][0-9]|3[01])[\.\/-](?:0[1-9]|1[012])[\.\/-](?:19|20)\d{2}\b",
    
    # --- Универсальный (для ручной разметки) ---
    "Generic / Any Content": r".+" 
}

# 3. ПОДОЗРИТЕЛЬНЫЕ НАЗВАНИЯ (Для Metadata Profiling)
SUSPICIOUS_NAMES = {
    "email": "Email", "mail": "Email",
    "phone": "Phone (RU)", "mobile": "Phone (RU)",
    "passport": "Passport (RU)", "pass_doc": "Passport (RU)",
    "inn": "INN (Individual)",
    "snils": "SNILS",
    "credit_card": "Credit Card", "card_num": "Credit Card",
    "fio": "FIO (RU)", "full_name": "FIO (RU)", "name": "FIO (RU)", "lastname": "FIO (RU)",
    "birth": "Date of Birth", "dob": "Date of Birth",
    "address": "Address (Risk)", "city": "Address (Risk)", "region": "Address (Risk)"
}

# --- БАЗОВЫЕ ФУНКЦИИ БД ---

# --- УПРАВЛЕНИЕ ПУЛОМ СОЕДИНЕНИЙ ---

@st.cache_resource(show_spinner=False)
def get_db_pool(db_config):
    """
    Создает пул соединений. 
    Кешируется Streamlit: если конфиг не менялся, вернет уже готовый пул.
    """
    try:
        # ThreadedConnectionPool подходит для Streamlit (многопоточный)
        # minconn=1, maxconn=20
        return pool.ThreadedConnectionPool(1, 20, **db_config)
    except Exception as e:
        print(f"Pool Creation Error: {e}")
        return None

def get_connection(db_config=None):
    """Получает соединение из пула с механизмом самоисцеления"""
    target_conf = db_config if db_config else DB_CONFIG
    
    try:
        # 1. Получаем объект пула
        db_pool = get_db_pool(target_conf)
        if not db_pool:
            return "Error creating connection pool"
            
        # 2. Пытаемся взять соединение (nowait=False ждет, но мы ловим переполнение)
        conn = db_pool.getconn()
        return conn
        
    except pool.PoolError:
        # 3. ПОЙМАЛИ ОШИБКУ "Pool exhausted"!
        print("⚠️ Pool exhausted! Performing self-healing (clearing cache)...")
        
        # Сбрасываем кэш ресурсов Streamlit (уничтожаем старый пул)
        st.cache_resource.clear()
        
        # Создаем новый пул с нуля
        db_pool = get_db_pool(target_conf)
        
        # Пробуем взять соединение снова
        try:
            return db_pool.getconn()
        except Exception as e:
            return f"Critical Pool Error after reset: {e}"
            
    except Exception as e:
        return str(e)

def close_connection(conn, db_config=None):
    """
    ВАЖНО: Не закрывает соединение, а возвращает его в пул!
    """
    target_conf = db_config if db_config else DB_CONFIG
    try:
        db_pool = get_db_pool(target_conf)
        if db_pool and conn:
            db_pool.putconn(conn)
    except Exception as e:
        print(f"Error returning connection to pool: {e}")

def get_all_tables(db_config=None):
    """Получает список всех таблиц в схеме public"""
    conn = get_connection(db_config) # <--- Передаем конфиг
    if isinstance(conn, str): return []
    
    cur = conn.cursor()
    cur.execute("SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'")
    tables = [row[0] for row in cur.fetchall()]
    
    cur.close()
    close_connection(conn, db_config) # <--- Теперь db_config известен
    return tables

# --- УПРАВЛЕНИЕ НАСТРОЙКАМИ (DATA GOVERNANCE) ---

def init_settings_table(db_config=None):
    """Создает таблицу для хранения ручной разметки колонок"""
    conn = get_connection(db_config) # <--- Передаем конфиг
    if isinstance(conn, str): return
    
    cur = conn.cursor()
    try:
        cur.execute("CREATE SCHEMA IF NOT EXISTS pii_guard;")
        cur.execute("""
            CREATE TABLE IF NOT EXISTS pii_guard.column_settings (
                table_name TEXT,
                column_name TEXT,
                status TEXT, -- 'AUTO', 'IGNORE', 'FORCE_PII'
                pii_type TEXT, -- Если FORCE_PII, то какой тип (например 'Email')
                updated_at TIMESTAMP DEFAULT NOW(),
                PRIMARY KEY (table_name, column_name)
            );
        """)
        conn.commit()
    except Exception as e:
        conn.rollback()
        print(f"Settings Init Error: {e}")
    finally:
        cur.close()
        close_connection(conn, db_config) # <--- Теперь db_config известен

def get_column_settings(db_config=None):
    """Возвращает словарь настроек {(table, col): {'status': ..., 'type': ...}}"""
    # init_settings_table вызовем внутри init_db_security, тут можно пропустить для скорости
    conn = get_connection(db_config)
    if isinstance(conn, str): return {}
    cur = conn.cursor()
    try:
        cur.execute("SELECT table_name, column_name, status, pii_type FROM pii_guard.column_settings")
        rows = cur.fetchall()
        settings = {}
        for r in rows:
            settings[(r[0], r[1])] = {"status": r[2], "type": r[3]}
        return settings
    except Exception as e:
        print(f"Settings load error: {e}")
        return {}
    finally:
        cur.close()
        close_connection(conn, db_config)

VALID_STATUSES = {'AUTO', 'IGNORE', 'FORCE_PII'}

def save_batch_settings(updates, db_config=None):
    """
    Массовое сохранение настроек.
    updates: список словарей [{'table':..., 'col':..., 'status':..., 'type':...}]
    """
    conn = get_connection(db_config)
    if isinstance(conn, str): return False
    cur = conn.cursor()
    try:
        query = """
            INSERT INTO pii_guard.column_settings (table_name, column_name, status, pii_type, updated_at)
            VALUES (%s, %s, %s, %s, NOW())
            ON CONFLICT (table_name, column_name)
            DO UPDATE SET status = EXCLUDED.status, pii_type = EXCLUDED.pii_type, updated_at = NOW();
        """
        # Фильтруем записи с недопустимым статусом перед сохранением
        valid_updates = []
        for x in updates:
            if x['status'] not in VALID_STATUSES:
                print(f"⚠️ Недопустимый статус '{x['status']}' для {x['table']}.{x['col']}, пропускаем.")
                continue
            valid_updates.append(x)

        data = [(x['table'], x['col'], x['status'], x['type']) for x in valid_updates]
        cur.executemany(query, data)
        conn.commit()
        return True
    except Exception as e:
        print(e)
        conn.rollback()
        return False
    finally:
        cur.close()
        close_connection(conn, db_config)

# --- ЯДРО СКАНИРОВАНИЯ ---

def is_technical_column(col_name):
    """Эвристика: проверяет, похоже ли название на техническое поле"""
    col_lower = col_name.lower()
    for kw in SKIP_COLUMN_KEYWORDS:
        if kw in col_lower:
            # Исключение: если есть слово 'birth', то это не техническая дата
            if 'birth' in col_lower or 'dob' in col_lower:
                return False
            return True
    return False

def check_date_context(date_str):
    """
    Проверяет год в дате.
    True  -> Похоже на дату рождения (1920 — текущий год включительно).
    False -> Будущая дата или слишком давняя.
    Убрали жёсткий отсечатель «последние 5 лет» — он отбрасывал реальные ДР молодых людей.
    """
    try:
        years = re.findall(r"(?:19|20)\d{2}", date_str)
        if not years: return False

        year = int(years[0])
        current_year = datetime.datetime.now().year

        # Будущие даты точно не ДР
        if year > current_year: return False
        # Слишком старая дата
        if year < 1920: return False

        return True
    except Exception:
        return False

def scan_database(excluded_tables=None, active_patterns=None, db_config=None, limit_rows=2000, progress_callback=None):
    """
    progress_callback(current, total, table, col) — вызывается на каждом шаге,
    чтобы UI мог показывать прогресс в реальном времени.
    """
    if excluded_tables is None: excluded_tables = []
    if active_patterns is None: active_patterns = PII_PATTERNS.copy()

    # 1. Получаем настройки (Ручную разметку)
    settings = get_column_settings(db_config)

    # 2. Получаем список всех текстовых/дата/json колонок
    conn = get_connection(db_config)
    if isinstance(conn, str): return []
    cur = conn.cursor()
    cur.execute("""
        SELECT table_name, column_name
        FROM information_schema.columns
        WHERE table_schema = 'public'
          AND data_type IN (
            'character varying', 'text',
            'date', 'timestamp without time zone', 'timestamp with time zone',
            'json', 'jsonb'
          );
    """)
    all_columns = cur.fetchall()

    findings = []
    total_cols = len(all_columns)
    print(f"🚀 Старт умного сканирования. Всего колонок: {total_cols}")

    for idx, (table, col) in enumerate(all_columns):
        if progress_callback:
            progress_callback(idx, total_cols, table, col)
        if table in excluded_tables: continue
        
        # --- ШАГ 1: ПРОВЕРКА НАСТРОЕК (Data Governance) ---
        col_setting = settings.get((table, col), {})
        status = col_setting.get('status', 'AUTO')
        
        if status == 'IGNORE':
            continue # Рукой помечено "Игнорировать"
            
        if status == 'AUTO':
            # Автоматический режим: применяем эвристику стоп-слов
            if is_technical_column(col):
                continue
                
        # --- ШАГ 2: ПОДГОТОВКА ПАТТЕРНОВ ---
        # Если FORCE_PII, ищем только конкретный тип
        target_patterns = active_patterns
        if status == 'FORCE_PII':
            forced_type = col_setting.get('type')
            if forced_type and forced_type in PII_PATTERNS:
                target_patterns = {forced_type: PII_PATTERNS[forced_type]}
        
        # --- ШАГ 3: ЧТЕНИЕ ДАННЫХ ---
        try:
            query = sql.SQL("SELECT id::text, {}::text FROM {} WHERE {} IS NOT NULL LIMIT {}").format(
                sql.Identifier(col),
                sql.Identifier(table),
                sql.Identifier(col),
                sql.Literal(limit_rows)
            )
            cur.execute(query)
            rows = cur.fetchall()
        except Exception as e:
            print(f"⚠️ Ошибка чтения {table}.{col}: {e}")
            continue

        # --- ШАГ 4: АНАЛИЗ КОНТЕНТА ---
        for row_id, val in rows:
            text_val = str(val)
            
            for p_name, p_regex in target_patterns.items():
                if re.search(p_regex, text_val):
                    
                    # Контекстная проверка для Дат
                    if p_name == "Date of Birth":
                        if not check_date_context(text_val):
                            continue 
                            
                    findings.append({
                        "table": table,
                        "column": col,
                        "id": row_id,
                        "type": p_name,
                        "value": text_val
                    })
                    break # Нашли угрозу -> следующая строка

    cur.close()
    close_connection(conn, db_config)
    return findings

def scan_metadata_for_hints(db_config=None):
    """Анализ названий колонок (Metadata Profiling)"""
    conn = get_connection(db_config) # <--- Передаем конфиг
    if isinstance(conn, str): return []
    
    cur = conn.cursor()
    cur.execute("""
        SELECT table_name, column_name 
        FROM information_schema.columns 
        WHERE table_schema = 'public'
    """)
    columns = cur.fetchall()
    hints = []
    
    for table, col in columns:
        col_lower = col.lower()
        for keyword, pii_type in SUSPICIOUS_NAMES.items():
            if keyword in col_lower:
                hints.append({
                    "table": table,
                    "column": col,
                    "suspected_type": pii_type
                })
                break
    cur.close()
    close_connection(conn, db_config) # <--- Теперь db_config известен
    return hints

# --- ФУНКЦИИ БЕЗОПАСНОСТИ И ОБЕЗЛИЧИВАНИЯ ---

def init_db_security(db_config=None):
    """Применяет SQL-скрипт защиты и инициализирует настройки"""
    # 1. Создаем таблицу настроек
    # (в идеале init_settings_table тоже должна принимать конфиг, но пока опустим для краткости)
    init_settings_table(db_config)
    
    # 2. Накатываем логику аудита и маскирования
    conn = get_connection(db_config) # <--- Передаем конфиг
    if isinstance(conn, str): return
    cur = conn.cursor()
    try:
        with open("init_db_logic.sql", "r", encoding="utf-8") as f:
            cur.execute(f.read())
        
        # Включаем аудит для всех таблиц
        cur.execute("SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'")
        tables = [row[0] for row in cur.fetchall()]
        for table in tables:
            cur.execute("CALL pii_guard.enable_audit(%s)", (table,))
            
        conn.commit()
        print(f"🛡️ Безопасность БД активирована.")
    except Exception as e:
        conn.rollback()
        print(f"❌ Ошибка инициализации DB Security: {e}")
    finally:
        cur.close()
        close_connection(conn, db_config)

def mask_data(findings, mode='mask', db_config=None):
    """Обезличивание данных (SQL mask или Python Faker)"""
    if mode not in ('mask', 'fake'):
        print(f"⚠️ Неверный режим: '{mode}', используется 'mask'")
        mode = 'mask'

    conn = get_connection(db_config)
    if isinstance(conn, str): return 0

    cur = conn.cursor()
    count = 0
    try:
        if mode == 'mask':
            # Быстрый SQL способ
            unique_tasks = set((f['table'], f['column']) for f in findings)
            for table, col in unique_tasks:
                # Безопасный вызов процедуры через параметры (защита от инъекций в именах)
                cur.execute("CALL pii_guard.fast_mask(%s, %s)", (table, col))
            count = len(findings)
        else:
            # Умный Faker способ
            for item in findings:
                table = item['table']
                col = item['column']
                row_id = item['id']
                pii_type = item['type']
                
                # ... (Генерация new_value - оставляем как было) ...
                new_value = "****"
                if pii_type == 'Email': new_value = fake.email()
                elif 'Phone' in pii_type: new_value = f"+79{fake.random_int(100000000, 999999999)}"
                elif 'Passport' in pii_type: new_value = f"{fake.random_int(1000, 9999)} {fake.random_int(100000, 999999)}"
                elif 'Credit' in pii_type: new_value = fake.credit_card_number()
                elif 'INN' in pii_type: new_value = str(fake.random_int(100000000000, 999999999999))
                elif 'FIO' in pii_type: new_value = fake.name()
                elif 'Date' in pii_type: new_value = fake.date_of_birth().strftime("%d.%m.%Y")
                elif 'Address' in pii_type: new_value = fake.address()
                else: new_value = fake.word()

                try:
                    # Используем sql.Identifier для защиты имен таблиц/колонок
                    query = sql.SQL("UPDATE {} SET {} = %s WHERE id = %s").format(
                        sql.Identifier(table),
                        sql.Identifier(col)
                    )
                    cur.execute(query, (new_value, row_id))
                    count += 1
                except Exception as e:
                    print(f"⚠️ Ошибка маскирования {table}.{col} id={row_id}: {e}")
                    
        conn.commit()
        db_name_log = db_config['dbname'] if db_config else "unknown_db"
        log_event("MASK", db_name_log, f"Обезличено {count} записей ({mode})")
    except Exception as e:
        conn.rollback()
        print(f"❌ Ошибка маскирования: {e}")
        count = 0
    finally:
        cur.close()
        close_connection(conn, db_config)
    return count

def _validate_identifier(name):
    """Проверяет, что имя БД/таблицы содержит только безопасные символы."""
    if not re.match(r'^[a-zA-Z0-9_]+$', name):
        raise ValueError(f"Небезопасное имя объекта БД: '{name}'")
    return name

def generate_sanitized_dump(findings, mode='mask', db_config=None):
    """
    Создает безопасную копию БД, обезличивает её и делает дамп.
    Исключает таблицу аудита из дампа!
    """
    target_conf = db_config if db_config else DB_CONFIG

    original_db = _validate_identifier(target_conf['dbname'])
    temp_db = _validate_identifier(f"{original_db}_anon_temp")
    dump_file = "/tmp/sanitized_dump.sql"
    
    # Коннект к системной базе postgres для клонирования
    admin_config = target_conf.copy()
    admin_config['dbname'] = 'postgres'
    
    # Важно: для клонирования нужно подключиться к postgres, а не к целевой БД
    try:
        conn = psycopg2.connect(**admin_config)
        conn.autocommit = True
        cur = conn.cursor()
    except Exception as e:
        print(f"Connection error: {e}")
        return None
    
    try:
        print(f"📦 Начало создания безопасного дампа...")
        
        # 1. Кикаем подключения к оригиналу
        cur.execute(
            sql.SQL("""
                SELECT pg_terminate_backend(pg_stat_activity.pid)
                FROM pg_stat_activity
                WHERE pg_stat_activity.datname = {}
                  AND pid <> pg_backend_pid()
            """).format(sql.Literal(original_db))
        )

        # 2. Клонируем БД (DDL не поддерживает параметры — используем sql.Identifier после валидации)
        cur.execute(sql.SQL("DROP DATABASE IF EXISTS {}").format(sql.Identifier(temp_db)))
        cur.execute(
            sql.SQL("CREATE DATABASE {} WITH TEMPLATE {}").format(
                sql.Identifier(temp_db), sql.Identifier(original_db)
            )
        )
        
        # 3. Подменяем конфиг на временный (копию словаря, чтобы не испортить оригинал!)
        temp_config = target_conf.copy()
        temp_config['dbname'] = temp_db
        
        # 4. Обезличиваем КОПИЮ (передаем временный конфиг!)
        print(f"🧹 Обезличиваем копию...")
        if not findings:
            print("⚠️ Находок нет, дамп будет оригинальным.")
        else:
            # Важно: передаем temp_config, чтобы маскировать КОПИЮ, а не оригинал
            count = mask_data(findings, mode=mode, db_config=temp_config)
            # Примечание: если mask_data вернет 0 ошибок, считаем успехом
        
        # 5. Делаем pg_dump
        env = os.environ.copy()
        env['PGPASSWORD'] = target_conf['password']
        
        cmd = [
            'pg_dump',
            '-h', target_conf['host'],
            '-p', target_conf['port'],
            '-U', target_conf['user'],
            '--exclude-table-data=pii_guard.audit_log',
            '-f', dump_file,
            temp_db
        ]
        
        subprocess.run(cmd, env=env, check=True)
        print(f"💾 Дамп готов: {dump_file}")
        
        return dump_file

    except Exception as e:
        print(f"❌ Ошибка дампа: {e}")
        return None
        
    finally:
        # Уборка
        try:
            cur.execute(sql.SQL("DROP DATABASE IF EXISTS {}").format(sql.Identifier(temp_db)))
        except Exception as e:
            print(f"Cleanup error (temp db): {e}")
        cur.close()
        conn.close()

# --- ОТЧЕТЫ (PDF) ---

class PDFReport(FPDF):
    def header(self):
        try:
            self.add_font('DejaVu', '', '/app/DejaVuSans.ttf')
            self.set_font('DejaVu', '', 10)
        except:
            self.set_font('Helvetica', '', 10)
        self.cell(0, 10, 'Postgres PII Guard - Security Scan Report', align='R')
        self.ln(15)
    
    def footer(self):
        self.set_y(-15)
        self.set_font('Helvetica', 'I', 8)
        self.cell(0, 10, f'Page {self.page_no()}', align='C')

def create_pdf_report(findings):
    pdf = PDFReport()
    try: pdf.add_font('DejaVu', '', '/app/DejaVuSans.ttf')
    except: pass
    
    pdf.add_page()
    try: pdf.set_font('DejaVu', '', 16)
    except: pdf.set_font('Helvetica', 'B', 16)
        
    pdf.cell(0, 10, 'Отчет о безопасности базы данных', new_x="LMARGIN", new_y="NEXT", align='C')
    pdf.ln(10)
    
    # Метаданные
    pdf.set_font_size(12)
    now = datetime.datetime.now().strftime("%d.%m.%Y %H:%M")
    pdf.cell(0, 10, f'Дата сканирования: {now}', new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 10, f'Всего найдено угроз: {len(findings)}', new_x="LMARGIN", new_y="NEXT")
    pdf.ln(5)
    
    # Таблица
    pdf.set_fill_color(200, 220, 255)
    headers = [("ID", 15), ("Тип", 50), ("Таблица", 40), ("Значение", 85)]
    for title, width in headers:
        pdf.cell(width, 10, title, border=1, fill=True)
    pdf.ln()
    
    pdf.set_font_size(10)
    for item in findings[:100]:
        row_id = str(item.get('id', ''))
        row_type = str(item.get('type', ''))
        row_table = str(item.get('table', ''))
        row_val = str(item.get('value', ''))[:40]

        pdf.cell(15, 10, row_id, border=1)
        pdf.cell(50, 10, row_type, border=1)
        pdf.cell(40, 10, row_table, border=1)
        pdf.cell(85, 10, row_val, border=1)
        pdf.ln()
        
    return bytes(pdf.output())

# --- ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ (ДЛЯ EXPLORER И ЛОГОВ) ---

def get_db_schema_info(db_config=None):
    """
    Возвращает:
    1. tables_info: Словарь { 'table_name': 'pk_column_name' }
    2. rels: Список связей [('source_table', 'target_table')]
    """
    conn = get_connection(db_config)
    if isinstance(conn, str): return {}, []
    
    cur = conn.cursor()
    try:
        # 1. Получаем список таблиц и их Primary Keys
        # Используем LEFT JOIN, чтобы найти таблицы даже без PK
        cur.execute("""
            SELECT t.table_name, kcu.column_name
            FROM information_schema.tables t
            LEFT JOIN information_schema.table_constraints tc 
                ON t.table_name = tc.table_name 
                AND tc.constraint_type = 'PRIMARY KEY'
                AND tc.table_schema = 'public'
            LEFT JOIN information_schema.key_column_usage kcu 
                ON tc.constraint_name = kcu.constraint_name
                AND tc.table_schema = kcu.table_schema
            WHERE t.table_schema = 'public'
            ORDER BY t.table_name;
        """)
        rows = cur.fetchall()
        
        # Собираем словарь: {'users': 'id', 'logs': 'no_pk'}
        tables_info = {}
        for table, pk in rows:
            # Если PK составной, он может прийти несколькими строками, 
            # но для упрощения берем первый или перезаписываем.
            if table not in tables_info:
                tables_info[table] = pk if pk else ""
            elif pk:
                # Если составной ключ, дописываем через запятую
                tables_info[table] += f", {pk}"

        # 2. Получаем связи (Foreign Keys) - без изменений
        cur.execute("""
            SELECT tc.table_name, ccu.table_name
            FROM information_schema.table_constraints AS tc
            JOIN information_schema.key_column_usage AS kcu ON tc.constraint_name = kcu.constraint_name
            JOIN information_schema.constraint_column_usage AS ccu ON ccu.constraint_name = tc.constraint_name
            WHERE constraint_type = 'FOREIGN KEY' AND tc.table_schema='public';
        """)
        rels = cur.fetchall()
        
        return tables_info, rels
        
    except Exception as e:
        print(f"Schema Error: {e}")
        return {}, []
    finally:
        cur.close()
        close_connection(conn, db_config)

def get_table_statistics(table_name, db_config=None):
    conn = get_connection(db_config)
    if isinstance(conn, str): return {'rows': 0, 'size': '0', 'columns': []}
    cur = conn.cursor()
    stats = {}
    try:
        cur.execute(sql.SQL("SELECT COUNT(*) FROM {}").format(sql.Identifier(table_name)))
        stats['rows'] = cur.fetchone()[0]
        cur.execute(
            sql.SQL("SELECT pg_size_pretty(pg_total_relation_size({}::regclass))").format(sql.Literal(table_name))
        )
        stats['size'] = cur.fetchone()[0]
        cur.execute(
            "SELECT column_name, data_type, is_nullable FROM information_schema.columns "
            "WHERE table_schema = 'public' AND table_name = %s ORDER BY ordinal_position",
            (table_name,)
        )
        stats['columns'] = cur.fetchall()
    except Exception as e:
        print(f"Statistics error for {table_name}: {e}")
        stats = {'rows': 0, 'size': 'err', 'columns': []}
    cur.close()
    close_connection(conn, db_config)
    return stats

def get_table_sample(table_name, limit=5, db_config=None):
    conn = get_connection(db_config)
    if isinstance(conn, str): return []
    cur = conn.cursor()
    try:
        cur.execute(sql.SQL("SELECT * FROM {} LIMIT 0").format(sql.Identifier(table_name)))
        col_names = [desc[0] for desc in cur.description]
        cur.execute(sql.SQL("SELECT * FROM {} LIMIT %s").format(sql.Identifier(table_name)), (limit,))
        rows = cur.fetchall()
        sample = [dict(zip(col_names, row)) for row in rows]
        return sample
    except Exception as e:
        print(f"Sample error for {table_name}: {e}")
        return []
    finally:
        cur.close()
        close_connection(conn, db_config)

def get_db_schema_details(db_config=None):
    """Детальная инфа для вкладки Data Governance"""
    conn = get_connection(db_config) # <--- db_config
    if isinstance(conn, str): return []
    cur = conn.cursor()
    cur.execute("""
        SELECT table_name, column_name, data_type 
        FROM information_schema.columns 
        WHERE table_schema = 'public'
        ORDER BY table_name, column_name
    """)
    rows = cur.fetchall()
    cur.close()
    close_connection(conn, db_config)
    return rows

# SQLite аудит (для локального лога приложения)
AUDIT_DB = "audit_log.db"

def init_audit_db():
    conn = sqlite3.connect(AUDIT_DB)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            action_type TEXT,
            target_db TEXT,
            details TEXT
        )
    """)
    conn.commit()
    conn.close()

def log_event(action_type, target_db, details):
    init_audit_db()
    conn = sqlite3.connect(AUDIT_DB)
    cur = conn.cursor()
    cur.execute("INSERT INTO audit_logs (action_type, target_db, details) VALUES (?, ?, ?)",
                (action_type, target_db, details))
    conn.commit()
    conn.close()

def get_audit_logs():
    init_audit_db()
    conn = sqlite3.connect(AUDIT_DB)
    cur = conn.cursor()
    cur.execute("SELECT timestamp, action_type, target_db, details FROM audit_logs ORDER BY id DESC LIMIT 50")
    rows = cur.fetchall()
    conn.close()
    return rows