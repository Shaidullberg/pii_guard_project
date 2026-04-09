# Используем легкий образ Python
FROM python:3.10-slim

# Устанавливаем рабочую директорию
WORKDIR /app

# 1. Устанавливаем системные зависимости
# graphviz - для схем
# fonts-dejavu - шрифт для PDF (вместо скачивания wget-ом)
RUN apt-get update && apt-get install -y \
    graphviz \
    fonts-dejavu \
    postgresql-client \
    && rm -rf /var/lib/apt/lists/*

# 2. Создаем ссылку на шрифт
# Пакет ставит шрифт в /usr/share/..., а наш скрипт ищет его в корне /app.
# Делаем "обманку" (symlink), чтобы код не переписывать.
RUN ln -s /usr/share/fonts/truetype/dejavu/DejaVuSans.ttf /app/DejaVuSans.ttf

# 3. Копируем зависимости python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 4. Копируем код приложения и SQL скрипты
COPY . .

# 5. Открываем порт Streamlit
EXPOSE 8501

# 6. Healthcheck (проверка жизни приложения)
HEALTHCHECK CMD curl --fail http://localhost:8501/_stcore/health || exit 1

# 7. Запуск приложения
# Сначала наполняем БД, потом запускаем интерфейс
ENTRYPOINT ["sh", "-c", "python seed_data_relational.py && streamlit run app.py --server.port=8501 --server.address=0.0.0.0"]