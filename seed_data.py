import psycopg2
import random
from faker import Faker

# Инициализируем генератор российских данных
fake = Faker('ru_RU')

# Настройки (как в backend.py)
DB_CONFIG = {
    "dbname": "testdb",
    "user": "admin",
    "password": "secret_password",
    "host": "localhost",
    "port": "5433" 
}

def create_tables(cur):
    # 1. Сносим старые таблицы, чтобы начать с чистого листа
    print("🧹 Удаляю старые таблицы...")
    tables = ["customers", "employees", "orders", "support_chat", "system_logs"]
    for t in tables:
        cur.execute(f"DROP TABLE IF EXISTS {t} CASCADE;")

    # 2. Создаем новые таблицы с разной структурой
    print("🏗️ Создаю новую структуру БД...")
    
    # Таблица сотрудников (HR данные)
    cur.execute("""
        CREATE TABLE employees (
            id SERIAL PRIMARY KEY,
            full_name TEXT,
            private_phone TEXT,
            passport_data TEXT,
            position TEXT
        );
    """)

    # Таблица заказов (Данные спрятаны в комментариях)
    cur.execute("""
        CREATE TABLE orders (
            id SERIAL PRIMARY KEY,
            order_number VARCHAR(20),
            delivery_address TEXT,
            courier_notes TEXT -- Сюда будем прятать телефоны
        );
    """)

    # Чат поддержки (Полный хаос)
    cur.execute("""
        CREATE TABLE support_chat (
            id SERIAL PRIMARY KEY,
            user_id INT,
            message_body TEXT, -- Сюда будем прятать СНИЛС, Паспорта, Email
            created_at TIMESTAMP DEFAULT NOW()
        );
    """)

    # Логи системы (Технические данные)
    cur.execute("""
        CREATE TABLE system_logs (
            id SERIAL PRIMARY KEY,
            log_level VARCHAR(10),
            event_source VARCHAR(50),
            details TEXT -- Сюда спрячем JSON с email
        );
    """)

def generate_data(conn, cur):
    print("🎲 Начинаю заливку реалистичных данных...")

    # --- 1. Заполняем Employees (50 шт) ---
    # Тут всё четко: паспорт в колонке паспорта
    for _ in range(50):
        cur.execute(
            "INSERT INTO employees (full_name, private_phone, passport_data, position) VALUES (%s, %s, %s, %s)",
            (fake.name(), f"+79{fake.random_int(100000000, 999999999)}", 
             f"{fake.random_int(1000, 9999)} {fake.random_int(100000, 999999)}", fake.job())
        )

    # --- 2. Заполняем Orders (100 шт) ---
    # В 30% случаев пишем "Позвоните мне: +7..." в комментарий курьеру
    for _ in range(100):
        notes = "Код домофона 45к2."
        if random.random() < 0.3:
            notes += f" Если что звоните: +79{fake.random_int(100000000, 999999999)}"
        
        cur.execute(
            "INSERT INTO orders (order_number, delivery_address, courier_notes) VALUES (%s, %s, %s)",
            (fake.bothify(text='ORD-####-????'), fake.address(), notes)
        )

    # --- 3. Заполняем Support Chat (100 шт) ---
    # Люди скидывают документы прямо в чат
    for _ in range(100):
        msg_type = random.choice(['clean', 'passport', 'snils', 'email'])
        message = fake.text(max_nb_chars=50)

        if msg_type == 'passport':
            message = f"Вот мой паспорт: {fake.random_int(1000, 9999)} {fake.random_int(100000, 999999)}, проверьте."
        elif msg_type == 'snils':
            # СНИЛС формат 123-456-789 00
            snils = f"{fake.random_int(100, 999)}-{fake.random_int(100, 999)}-{fake.random_int(100, 999)} {fake.random_int(10, 99)}"
            message = f"Мой СНИЛС для оформления: {snils}"
        elif msg_type == 'email':
            message = f"Отправьте чек на {fake.email()}"

        cur.execute(
            "INSERT INTO support_chat (user_id, message_body) VALUES (%s, %s)",
            (random.randint(1, 500), message)
        )

    # --- 4. Заполняем Logs (100 шт) ---
    # Иногда проскакивает Email в логах
    for _ in range(100):
        details = "Process finished successfully."
        if random.random() < 0.2:
            details = f"Error processing user {fake.email()}: Connection timeout."
            
        cur.execute(
            "INSERT INTO system_logs (log_level, event_source, details) VALUES (%s, %s, %s)",
            (random.choice(['INFO', 'ERROR', 'DEBUG']), "AuthService", details)
        )

    conn.commit()
    print("✅ База данных успешно наполнена разнородными данными!")

if __name__ == "__main__":
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cur = conn.cursor()
        create_tables(cur)
        generate_data(conn, cur)
        cur.close()
        conn.close()
    except Exception as e:
        print(f"❌ Ошибка: {e}")