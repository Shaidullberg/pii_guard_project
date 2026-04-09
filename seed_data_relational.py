import psycopg2
import random
from faker import Faker
import os
import backend  # <--- Импортируем наш бэкенд, чтобы вызвать функцию инициализации

# Инициализируем Faker
fake = Faker('ru_RU')

# Конфигурация (берем из ENV, как и везде)
DB_CONFIG = {
    "dbname": os.getenv("POSTGRES_DB", "testdb"),
    "user": os.getenv("POSTGRES_USER", "admin"),
    "password": os.getenv("POSTGRES_PASSWORD", "secret_password"),
    "host": os.getenv("DB_HOST", "localhost"),
    "port": os.getenv("DB_PORT", "5432")
}

def create_schema(cur):
    print("🏗️ Создаю реляционную структуру (с Foreign Keys)...")
    
    # 1. Удаляем всё старое (CASCADE удалит и зависимости)
    # Удаляем и схему pii_guard, чтобы пересоздать её начисто
    cur.execute("DROP SCHEMA IF EXISTS pii_guard CASCADE;")
    
    tables = ["payments", "orders", "profiles", "support_tickets", "users", "products"]
    for t in tables:
        cur.execute(f"DROP TABLE IF EXISTS {t} CASCADE;")

    # 2. Таблица Пользователей
    cur.execute("""
        CREATE TABLE users (
            id SERIAL PRIMARY KEY,
            username VARCHAR(50) NOT NULL,
            email VARCHAR(100) NOT NULL,
            registration_date DATE DEFAULT CURRENT_DATE
        );
    """)

    # 3. Таблица Профилей
# В функции create_schema -> таблица profiles
    cur.execute("""
    CREATE TABLE profiles (
        id SERIAL PRIMARY KEY,
        user_id INTEGER UNIQUE REFERENCES users(id) ON DELETE CASCADE,
        full_name TEXT, 
        birth_date TEXT,
        passport_details TEXT,
        snils TEXT,
        address TEXT
        );
    """)

    # 4. Таблица Заказов
    cur.execute("""
        CREATE TABLE orders (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
            order_number VARCHAR(20),
            total_amount DECIMAL(10, 2),
            created_at TIMESTAMP DEFAULT NOW()
        );
    """)

    # 5. Таблица Платежей
    cur.execute("""
        CREATE TABLE payments (
            id SERIAL PRIMARY KEY,
            order_id INTEGER REFERENCES orders(id) ON DELETE CASCADE,
            payment_method VARCHAR(20),
            credit_card_number VARCHAR(20),
            transaction_status VARCHAR(20)
        );
    """)

    # 6. Таблица Поддержки
    cur.execute("""
        CREATE TABLE support_tickets (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES users(id),
            subject VARCHAR(100),
            message_body TEXT,
            status VARCHAR(15)
        );
    """)

def generate_data(conn, cur):
    print("🎲 Генерирую связанные данные...")
    
    user_ids = []
    # --- 1. Users ---
    for _ in range(200):
        cur.execute(
            "INSERT INTO users (username, email) VALUES (%s, %s) RETURNING id",
            (fake.user_name(), fake.email())
        )
        user_ids.append(cur.fetchone()[0])

    # --- 2. Profiles ---
    for uid in user_ids:
        snils = f"{random.randint(100,999)}-{random.randint(100,999)}-{random.randint(100,999)} {random.randint(10,99)}"
        passport = f"{random.randint(1000,9999)} {random.randint(100000,999999)}"
        dob = fake.date_of_birth(minimum_age=18, maximum_age=90).strftime("%d.%m.%Y")
        cur.execute(
    "INSERT INTO profiles (user_id, full_name, birth_date, passport_details, snils, address) VALUES (%s, %s, %s, %s, %s, %s)",
    (uid, fake.name(), dob, passport, snils, fake.address())
        )

    # --- 3. Orders ---
    order_ids = []
    for _ in range(500):
        uid = random.choice(user_ids)
        cur.execute(
            "INSERT INTO orders (user_id, order_number, total_amount) VALUES (%s, %s, %s) RETURNING id",
            (uid, fake.bothify('ORD-#####'), random.uniform(100, 50000))
        )
        order_ids.append(cur.fetchone()[0])

    # --- 4. Payments ---
    for oid in order_ids:
        cc = fake.credit_card_number()
        cur.execute(
            "INSERT INTO payments (order_id, payment_method, credit_card_number, transaction_status) VALUES (%s, %s, %s, %s)",
            (oid, "Credit Card", cc, "SUCCESS")
        )

    # --- 5. Support Tickets ---
    for _ in range(150):
        uid = random.choice(user_ids)
        msg = fake.text()
        if random.random() < 0.3:
            msg += f"\nМой номер: +79{random.randint(100000000, 999999999)}"
        if random.random() < 0.2:
            msg += f"\nПаспорт забыл: {random.randint(1000,9999)} {random.randint(100000,999999)}"

        cur.execute(
            "INSERT INTO support_tickets (user_id, subject, message_body, status) VALUES (%s, %s, %s, %s)",
            (uid, "Проблема с заказом", msg, "OPEN")
        )

    conn.commit()
    print("✅ Данные сгенерированы.")

if __name__ == "__main__":
    try:
        # 1. Соединяемся и наполняем данными
        conn = psycopg2.connect(**DB_CONFIG)
        cur = conn.cursor()
        create_schema(cur)
        generate_data(conn, cur)
        cur.close()
        conn.close()
        
        # 2. ВАЖНО: Инициализируем систему безопасности (Схемы, Триггеры, Процедуры)
        # Передаём DB_CONFIG явно — не используем глобальный конфиг backend
        print("🛡️ Применяю патч безопасности...")
        backend.init_db_security(DB_CONFIG)
        print("✅ Патч безопасности применён.")

    except Exception as e:
        print(f"❌ Ошибка в скрипте seed: {e}")