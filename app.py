import streamlit as st
import pandas as pd
import backend
import graphviz
import os 

# 1. Настройка страницы
st.set_page_config(
    page_title="PII Guard Enterprise",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ==========================================
# ГЛОБАЛЬНЫЕ НАСТРОЙКИ (САЙДБАР)
# Выносим его из вкладок, чтобы переменные были видны ВЕЗДЕ
# ==========================================
with st.sidebar:
    st.header("🔌 Подключение к БД")
    
    # --- ФУНКЦИЯ-CALLBACK (БЕЗОПАСНАЯ) ---
    def load_env_vars():
        st.session_state['db_host'] = os.getenv("DB_HOST", "db")
        st.session_state['db_port'] = os.getenv("DB_PORT", "5432")
        st.session_state['db_name'] = os.getenv("POSTGRES_DB", "testdb")
        st.session_state['db_user'] = os.getenv("POSTGRES_USER", "admin")
        st.session_state['db_pass'] = os.getenv("POSTGRES_PASSWORD", "secret_password")
        # st.rerun() НЕ НУЖЕН! Streamlit сам обновится после коллбека

    # Кнопка теперь просто вызывает функцию
    st.button("📥 Загрузить из ENV (Docker)", on_click=load_env_vars, use_container_width=True)

    st.caption("Или введите вручную:")
    
    # Инициализация state (если пусто)
    if 'db_host' not in st.session_state: st.session_state['db_host'] = "db"
    if 'db_port' not in st.session_state: st.session_state['db_port'] = "5432"
    if 'db_name' not in st.session_state: st.session_state['db_name'] = "testdb"
    if 'db_user' not in st.session_state: st.session_state['db_user'] = "admin"
    if 'db_pass' not in st.session_state: st.session_state['db_pass'] = "secret_password"
    
    # Поля ввода
    # Поля ввода (Привязываем через key, чтобы работала кнопка ENV)
    # Обрати внимание: мы убрали argument 'value' и поставили 'key'
    
    # st.text_input вернет текущее значение, но также синхронизирует его с session_state
    st.text_input("Хост", key="db_host")
    st.text_input("Порт", key="db_port")
    st.text_input("База данных", key="db_name")
    st.text_input("Пользователь", key="db_user")
    st.text_input("Пароль", key="db_pass", type="password")
    
    # Важно: Так как мы используем key, значения уже лежат в st.session_state.
    # Нам нужно достать их в локальные переменные для формирования конфига ниже.
    db_host = st.session_state['db_host']
    db_port = st.session_state['db_port']
    db_name = st.session_state['db_name']
    db_user = st.session_state['db_user']
    db_pass = st.session_state['db_pass']

    use_ssl = st.checkbox("Использовать SSL (для Render/Cloud)", value=True)

    st.divider()
    
    scan_depth = st.slider("Глубина сканирования (строк)", min_value=100, max_value=50000, value=2000, step=100)

    current_db_config = {
        "dbname": db_name, "user": db_user, "password": db_pass,
        "host": db_host, "port": db_port,
    }
    # Если галочка стоит - добавляем режим SSL
    if use_ssl:
        current_db_config["sslmode"] = "require"
    # Для кнопки проверки соединения st.rerun тоже опасен, убираем его если был,
    # но здесь у нас просто логика. Оставляем как есть, тут нет st.rerun().
# Кнопка проверки
    if st.button("Проверить соединение", use_container_width=True):
        # 1. Создаем соединение
        conn = backend.get_connection(current_db_config)
        
        # 2. Проверяем результат
        if isinstance(conn, str):
            # Если вернулась строка — это текст ошибки
            st.error(f"❌ Ошибка: {conn}")
        else:
            # Если вернулся объект — успех
            st.success("✅ Соединение установлено!")
            # 3. Возвращаем соединение в пул (ВАЖНО!)
            backend.close_connection(conn, current_db_config)
            # 4. Инициализируем защиту
            backend.init_db_security(current_db_config)
    
    st.info("ℹ️ Убедитесь, что Docker-контейнер базы запущен.")


# ==========================================
# ОСНОВНОЙ ИНТЕРФЕЙС
# ==========================================
st.title("🛡️ Postgres PII Guard")
st.markdown("### Система защиты и обезличивания персональных данных")

# Создаем вкладки ПОСЛЕ того, как определили сайдбар и конфиг
tab_scan, tab_explore, tab_history = st.tabs(["🚀 Сканер и Защита", "🔭 Исследование БД", "📜 Журнал Аудита"])

# ==========================================
# ВКЛАДКА 1: ОСНОВНОЙ ФУНКЦИОНАЛ
# ==========================================
with tab_scan:
    # --- ЗДЕСЬ БОЛЬШЕ НЕТ st.sidebar ---
    
    # --- ЧАСТЬ 1: НАСТРОЙКА ОБЛАСТИ ПОИСКА ---
    st.markdown("#### 1. Настройка области поиска (ГДЕ искать?)")
    # ... дальше код без изменений ...
    
    all_tables = []
    try:
        # Убрали update_config(), используем backend напрямую с конфигом
        # Но для получения списка таблиц нам нужно передать конфиг в get_all_tables
        # (Нам придется чуть поправить backend.get_all_tables или временно оставить как есть, 
        # но лучше поправить. Давай пока оставим try-except, чтобы не ломать логику)
        conn_temp = backend.get_connection(current_db_config)
        if not isinstance(conn_temp, str):
            backend.close_connection(conn_temp, current_db_config)  # возвращаем в пул, не закрываем напрямую
            all_tables = backend.get_all_tables(current_db_config)
    except Exception as e:
        print(f"Не удалось получить список таблиц: {e}")

    col_white, col_info = st.columns([2, 1])
    with col_white:
        excluded_tables = st.multiselect(
            "🚫 Исключить таблицы из проверки (Whitelist):",
            options=all_tables,
            default=[],
            help="Выберите технические таблицы (например, migrations, logs), которые не нужно сканировать."
        )
    with col_info:
        if all_tables:
            active_count = len(all_tables) - len(excluded_tables)
            st.metric("Таблиц для проверки", f"{active_count} / {len(all_tables)}")
        else:
            st.warning("Нет подключения к БД")

    st.divider()

    # --- ЧАСТЬ 1.5: УМНЫЙ АНАЛИЗ МЕТАДАННЫХ ---
    st.markdown("#### 1.5. Умный анализ метаданных (Metadata Profiling)")
    
    with st.expander("🕵️ Проверить названия колонок (Быстрый анализ)", expanded=False):
        st.write("Система проанализирует названия столбцов и подскажет, где точно лежат данные.")
        
        if st.button("🔍 Запустить анализ метаданных"):
            hints = backend.scan_metadata_for_hints(current_db_config)
            if not hints:
                st.info("Подозрительных названий колонок не найдено.")
            else:
                st.warning(f"Найдено {len(hints)} колонок, которые судя по названию содержат перс. данные:")
                df_hints = pd.DataFrame(hints)
                st.dataframe(df_hints, use_container_width=True)
                st.info("💡 Совет: Вы можете настроить эти колонки во вкладке 'Исследование БД' -> 'Разметка данных'.")

# --- ЧАСТЬ 2: КОНСТРУКТОР ПАТТЕРНОВ ---
    st.markdown("#### 2. Критерии поиска (ЧТО искать?)")
    
    # 0. Сначала собираем базу правил, чтобы знать ключи
    default_patterns = backend.PII_PATTERNS
    custom_patterns = st.session_state.get('custom_patterns', {})
    all_available = {**default_patterns, **custom_patterns}
    
    # 1. Инициализируем список ВЫБРАННЫХ правил в session_state, если его нет
    # (По умолчанию выбираем всё)
    if 'selected_rules' not in st.session_state:
        st.session_state['selected_rules'] = list(all_available.keys())

    # Конструктор кастомных правил
    with st.expander("➕ Добавить свой критерий поиска (Конструктор правил)"):
        st.write("Выберите способ добавления нового правила:")
        t_lib, t_word, t_regex = st.tabs(["📚 Библиотека шаблонов", "🔤 Поиск слова", "🤓 RegEx (Pro)"])
        
        # Вкладка 1: Шаблоны
        with t_lib:
            # Расширенная библиотека
            PRESETS = {
                "--- Документы РФ ---": r"", 
                "Паспорт РФ (Серия Номер)": r"\b\d{4}[\s-]?\d{6}\b",
                "Загранпаспорт РФ": r"\b\d{2}[\s]?\d{7}\b",
                "СНИЛС": r"\b\d{3}[ -]?\d{3}[ -]?\d{3}[ -]?\d{2}\b",
                "Водительское (РФ)": r"\b\d{2}[\s]?[A-ZА-Я0-9]{2}[\s]?\d{6}\b",
                "ИНН (Физлицо)": r"\b\d{12}\b",
                "ИНН (Юрлицо)": r"\b\d{10}\b",
                
                "--- Финансы ---": r"",
                "Кредитная карта": r"\b(?:\d{4}[ -]?){3,4}\d{1,4}\b",
                "IBAN (Счет)": r"\b[A-Z]{2}\d{2}[A-Z0-9]{4,30}\b",
                "Bitcoin Wallet": r"\b(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}\b",
                
                "--- IT и Сети ---": r"",
                "IP-адрес (v4)": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
                "MAC-адрес": r"\b([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})\b",
                "JWT Token (Auth)": r"eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+",
                "AWS API Key": r"AKIA[0-9A-Z]{16}",
                
                "--- Общее ---": r"",
                "Дата рождения (ДД.ММ.ГГГГ)": r"\d{2}\.\d{2}\.\d{4}",
                "Email адрес": r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"
            }
            
            c1, c2 = st.columns([3, 1])
            with c1:
                sel_preset = st.selectbox("Выберите готовый шаблон:", list(PRESETS.keys()))
            with c2:
                st.write("") 
                st.write("") 
                if st.button("Добавить шаблон"):
                    val = PRESETS[sel_preset]
                    if val == r"":
                        st.warning("Это разделитель.")
                    else:
                        if 'custom_patterns' not in st.session_state: st.session_state['custom_patterns'] = {}
                        st.session_state['custom_patterns'][sel_preset] = val
                        
                        # --- FIX: Добавляем новый шаблон в список ВЫБРАННЫХ, не сбрасывая остальные ---
                        if sel_preset not in st.session_state['selected_rules']:
                            st.session_state['selected_rules'].append(sel_preset)
                            
                        st.success(f"✅ '{sel_preset}' добавлен!")
                        st.rerun()

        # Вкладка 2: Простое слово
        with t_word:
            c1, c2 = st.columns([3, 1])
            with c1:
                word_input = st.text_input("Введите слово или фразу (например: 'Секретно')")
            with c2:
                st.write("")
                st.write("")
                if st.button("Добавить слово") and word_input:
                    import re
                    name_key = f"Word: {word_input}"
                    if 'custom_patterns' not in st.session_state: st.session_state['custom_patterns'] = {}
                    st.session_state['custom_patterns'][name_key] = re.escape(word_input)
                    
                    # --- FIX: Добавляем в выбранные ---
                    if name_key not in st.session_state['selected_rules']:
                        st.session_state['selected_rules'].append(name_key)
                        
                    st.success(f"✅ Поиск '{word_input}' добавлен!")
                    st.rerun()

        # Вкладка 3: RegEx
        with t_regex:
            with st.form("custom_regex"):
                r_name = st.text_input("Название правила")
                r_val = st.text_input("RegEx паттерн")
                if st.form_submit_button("Добавить"):
                    if r_name and r_val:
                        if 'custom_patterns' not in st.session_state: st.session_state['custom_patterns'] = {}
                        st.session_state['custom_patterns'][r_name] = r_val
                        
                        # --- FIX: Добавляем в выбранные ---
                        if r_name not in st.session_state['selected_rules']:
                            st.session_state['selected_rules'].append(r_name)
                            
                        st.success("✅ RegEx добавлен!")
                        st.rerun()

    # Сборка всех правил (обновляем после добавлений)
    default_patterns = backend.PII_PATTERNS
    custom_patterns = st.session_state.get('custom_patterns', {})
    all_available = {**default_patterns, **custom_patterns}
    
    # --- FIX: Используем параметр KEY вместо DEFAULT ---
    # Streamlit теперь сам следит за переменной selected_rules
    selected_pattern_names = st.multiselect(
        "✅ Активные правила сканирования:",
        options=all_available.keys(),
        key='selected_rules' 
    )
    final_patterns = {k: all_available[k] for k in selected_pattern_names if k in all_available}

    st.divider()

    # --- ЧАСТЬ 3: ЗАПУСК ---
    col_run_info, col_run_btn = st.columns([3, 1])
    
    with col_run_info:
        st.info(f"Готов к сканированию. Активных правил: **{len(final_patterns)}**. Таблиц: **{len(all_tables) - len(excluded_tables)}**.")
    
    with col_run_btn:
        start_scan = st.button("🚀 ЗАПУСТИТЬ СКАНИРОВАНИЕ", type="primary", use_container_width=True)

    if start_scan:
        if not final_patterns:
            st.error("❌ Вы не выбрали ни одного правила!")
        else:
            progress_bar = st.progress(0, text="🔍 Подготовка к сканированию...")
            status_placeholder = st.empty()

            def update_progress(idx, total, table, col):
                pct = int((idx / max(total, 1)) * 100)
                progress_bar.progress(pct, text=f"🔍 Сканирую: **{table}.{col}** ({idx}/{total})")
                status_placeholder.caption(f"Таблица: `{table}` | Колонка: `{col}`")

            results = backend.scan_database(
                excluded_tables,
                final_patterns,
                db_config=current_db_config,
                limit_rows=scan_depth,
                progress_callback=update_progress
            )
            progress_bar.progress(100, text=f"✅ Сканирование завершено! Найдено: {len(results)}")
            status_placeholder.empty()
            st.session_state['scan_results'] = results
            log_msg = f"Найдено {len(results)} объектов. Таблиц: {len(all_tables)-len(excluded_tables)}."
            backend.log_event("SCAN", db_name, log_msg)

    # --- ЧАСТЬ 4: РЕЗУЛЬТАТЫ ---
    if 'scan_results' in st.session_state:
        results = st.session_state['scan_results']
        
        st.markdown("### 📊 Результаты анализа")
        
        if not results:
            st.success("🎉 Уязвимостей не найдено! (Либо сработали фильтры Ignore/Stop-words).")
        else:
            # 1. Метрики
            df = pd.DataFrame(results)
            m1, m2, m3, m4 = st.columns(4)
            m1.metric("Всего находок", len(df))
            m2.metric("Уникальных значений", df['value'].nunique())
            m3.metric("Таблиц затронуто", df['table'].nunique())
            m4.metric("Типов угроз", df['type'].nunique())
            
            # 2. График и Сводная таблица
            st.markdown("##### Распределение по типам")
            
            col_chart, col_summary = st.columns([1, 1])
            with col_chart:
                st.bar_chart(df['type'].value_counts())
            
            with col_summary:
                st.caption("Сводка по угрозам:")
                # Группируем: Таблица + Поле + Тип = Количество
                summary_df = df.groupby(['table', 'column', 'type']).size().reset_index(name='count')
                st.dataframe(summary_df, use_container_width=True, hide_index=True)

            # Детальный список прячем
            with st.expander("🕵️ Показать детальный список всех найденных строк (Raw Data)"):
                st.dataframe(df, use_container_width=True)
            
            # 3. Экспорт PDF
            st.markdown("##### 📄 Отчет")
            col_pdf, _ = st.columns([1, 3])
            with col_pdf:
                if len(results) > 100:
                    st.warning(f"⚠️ PDF содержит первые 100 из {len(results)} записей. Полный список — в таблице выше.")
                pdf_bytes = backend.create_pdf_report(results)
                st.download_button("📥 Скачать отчет (PDF)", pdf_bytes, "security_report.pdf", "application/pdf")
            
            st.divider()
            
            # --- 4. DANGER ZONE (ОБЕЗЛИЧИВАНИЕ) ---
            st.subheader("🛡️ Меры реагирования")
            
            # Оборачиваем в красный блок (error) для привлечения внимания
            with st.status("⚠️ ЗОНА ОБЕЗЛИЧИВАНИЯ (DANGER ZONE)", expanded=True, state="error"):
                st.write("Вы собираетесь применить необратимые изменения к базе данных.")
                
                c_opt, c_check = st.columns([1, 1])
                with c_opt:
                    mask_mode = st.radio(
                        "Метод защиты:", 
                        ["Маскирование (****)", "Синтетические данные (Faker)"],
                        horizontal=True
                    )
                with c_check:
                    st.write("") # Отступ
                    # ПРЕДОХРАНИТЕЛЬ
                    confirm_action = st.checkbox("Я понимаю, что данные в Production будут изменены", value=False)
                
                # Кнопка активна ТОЛЬКО если нажат чекбокс (disabled=not confirm_action)
                if st.button("🧹 ЗАПУСТИТЬ ПРОЦЕСС ОБЕЗЛИЧИВАНИЯ", type="primary", use_container_width=True, disabled=not confirm_action):
                    mode_code = 'fake' if 'Faker' in mask_mode else 'mask'
                    
                    with st.spinner("⏳ Применяю защиту..."):
                        # Передаем current_db_config (как делали в Шаге 1)
                        count = backend.mask_data(results, mode=mode_code, db_config=current_db_config)
                    
                    if count > 0:
                        st.success(f"✅ Успешно! Обработано {count} записей.")
                        st.balloons()
                        st.session_state['scan_results'] = [] 
                        import time
                        time.sleep(2)
                        st.rerun()
                    else:
                        st.error("Ошибка при обновлении или список угроз пуст.")

            st.divider()
            # ... (Ниже идет код "5. Экспорт Дампа", его не трогаем) ...

            # 5. Экспорт Дампа (НОВОЕ)
            st.subheader("📦 Экспорт для разработчиков (Sanitized Dump)")
            st.markdown("Создать безопасную копию базы, обезличить её и выгрузить в SQL. **Оригинал не меняется.**")
            
            col_dump_mode, col_dump_btn = st.columns([2, 1])
            with col_dump_mode:
                dump_mode = st.radio(
                    "Метод защиты дампа:", 
                    ["Маскирование (****)", "Синтетические данные (Faker)"],
                    horizontal=True,
                    key="dump_radio"
                )
            
            with col_dump_btn:
                st.write("")
                if st.button("🎁 СОЗДАТЬ БЕЗОПАСНЫЙ ДАМП", type="primary", use_container_width=True):
                    d_code = 'fake' if 'Faker' in dump_mode else 'mask'
                    with st.spinner("⏳ Клонирую БД, обезличиваю, удаляю логи и архивирую..."):
                        # ПЕРЕДАЕМ current_db_config!
                        dump_path = backend.generate_sanitized_dump(results, mode=d_code, db_config=current_db_config)
                        
                    if dump_path:
                        st.success("✅ Дамп готов!")
                        with open(dump_path, "rb") as f:
                            st.download_button("📥 Скачать SQL дамп", f, "sanitized_dump.sql", "application/sql")
                    else:
                        st.error("Ошибка создания дампа. См. консоль.")

# ==========================================
# ВКЛАДКА 2: ИССЛЕДОВАНИЕ (EXPLORER)
# ==========================================
with tab_explore:
    # Разделяем старый Explorer и новый Governance
    sub_viz, sub_gov = st.tabs(["📊 Визуализация и Данные", "🏷️ Управление Разметкой (Data Governance)"])
    
    # --- ПОДВКЛАДКА 1: ВИЗУАЛИЗАЦИЯ (СТАРЫЙ ФУНКЦИОНАЛ) ---
    with sub_viz:
        st.header("Структура базы данных")
        # Кнопка просто перезагружает страницу, конфиг уже в current_db_config
        st.button("🔄 Обновить данные схемы") 
            
        try:
            # Удаляем update_config() и передаем current_db_config
            tables_list, relations = backend.get_db_schema_info(current_db_config)
        except:
            tables_list, relations = [], []

# Обрати внимание: теперь мы распаковываем словарь tables_dict, а не список
        if tables_list: # Переменную можно не переименовывать, но по сути это теперь словарь
            tables_dict = tables_list 
            
            # ER Диаграмма
            with st.expander("🕸️ Визуализация связей (ER-Diagram)", expanded=True):
                graph = graphviz.Digraph()
                # Настройки графа для красоты
                graph.attr(rankdir='LR', splines='ortho') 
                graph.attr('node', shape='plaintext') # Используем HTML-стиль
                
                # Рисуем узлы (Таблицы + PK)
                for table_name, pk_col in tables_dict.items():
                    # HTML-метка для узла: Жирным имя таблицы, ниже PK
                    pk_label = f"PK: {pk_col}" if pk_col else ""
                    
                    label = f'''<<TABLE BORDER="0" CELLBORDER="1" CELLSPACING="0" BGCOLOR="#E3F2FD">
                        <TR><TD><B>{table_name}</B></TD></TR>
                        <TR><TD ALIGN="LEFT"><FONT POINT-SIZE="10" COLOR="#555555">🔑 {pk_label}</FONT></TD></TR>
                    </TABLE>>'''
                    
                    graph.node(table_name, label=label)

                # Рисуем связи
                for s, t in relations:
                    graph.edge(s, t, label='FK', color='#888888', style='dashed')
                    
                st.graphviz_chart(graph)
            
            st.divider()

  # Инспектор
            st.subheader("🔎 Детальный анализ таблицы")
            selected_table = st.selectbox("Выберите таблицу:", list(tables_list.keys()))
            
            if selected_table:
                # Передаем конфиг сюда
                stats = backend.get_table_statistics(selected_table, db_config=current_db_config)
                c1, c2, c3 = st.columns(3)
                c1.metric("Количество строк", stats['rows'])
                c2.metric("Размер на диске", stats['size'])
                c3.metric("Количество колонок", len(stats['columns']))
                
                st.markdown("**Структура полей:**")
                st.dataframe(pd.DataFrame(stats['columns'], columns=["Название", "Тип данных", "Может быть NULL"]), use_container_width=True)
                
                st.markdown(f"**👀 Предпросмотр данных ({selected_table}):**")
                # И сюда передаем конфиг
                sample_data = backend.get_table_sample(selected_table, db_config=current_db_config)
                if sample_data:
                    st.dataframe(pd.DataFrame(sample_data), use_container_width=True)
                else:
                    st.info("Таблица пуста.")
        else:
            st.warning("Нет подключения или таблиц.")

# --- ПОДВКЛАДКА 2: DATA GOVERNANCE (НОВЫЙ ФУНКЦИОНАЛ) ---
    with sub_gov:
        st.header("🏷️ Разметка данных (Data Governance)")
        st.markdown("Здесь вы можете вручную указать системе, какие колонки содержат персональные данные.")
        
        # 1. Загрузка данных
        try:
            # Получаем схему и текущие настройки
            all_cols_info = backend.get_db_schema_details(current_db_config)
            current_settings = backend.get_column_settings(current_db_config)
        except:
            all_cols_info, current_settings = [], {}
            # st.error("Ошибка загрузки настроек") # Можно скрыть, если база не подключена

        if all_cols_info:
            # 2. Подготовка DataFrame для редактора
            data_list = []
            for t_name, c_name, c_type in all_cols_info:
                # Получаем текущий статус или дефолт
                setting = current_settings.get((t_name, c_name), {})
                curr_stat = setting.get('status', 'AUTO')
                curr_type = setting.get('type', None)
                
                data_list.append({
                    "Таблица": t_name,
                    "Колонка": c_name,
                    "Тип БД": c_type,
                    "Статус": curr_stat,
                    "Тип PII (если Force)": curr_type
                })
            
            df_gov = pd.DataFrame(data_list)

            # 3. Редактор данных (Excel-like)
            st.info("💡 Отредактируйте статусы в таблице и нажмите 'Сохранить изменения' внизу.")
            
            edited_df = st.data_editor(
                df_gov,
                column_config={
                    "Таблица": st.column_config.TextColumn(disabled=True),
                    "Колонка": st.column_config.TextColumn(disabled=True),
                    "Тип БД": st.column_config.TextColumn(disabled=True),
                    "Статус": st.column_config.SelectboxColumn(
                        "Режим проверки",
                        help="AUTO: Умный поиск\nIGNORE: Не сканировать\nFORCE_PII: Считать утечкой",
                        width="medium",
                        options=[
                            "AUTO",
                            "IGNORE", 
                            "FORCE_PII"
                        ],
                        required=True
                    ),
                    "Тип PII (если Force)": st.column_config.SelectboxColumn(
                        "Тип данных",
                        help="Укажите тип данных, если выбран режим FORCE_PII",
                        width="medium",
                        options=list(backend.PII_PATTERNS.keys()),
                        required=False
                    )
                },
                hide_index=True,
                use_container_width=True,
                height=500,
                key="gov_editor"
            )

            # 4. Кнопка сохранения
            if st.button("💾 Сохранить изменения", type="primary"):
                # Сравниваем и ищем изменения (или просто сохраняем всё, что проще для MVP)
                updates = []
                # Превращаем DF обратно в список словарей
                for index, row in edited_df.iterrows():
                    # Простая логика: сохраняем все строки, где статус не AUTO или где он был изменен
                    # Для надежности в MVP сохраним просто всё, что в редакторе (upsert справится)
                    updates.append({
                        "table": row["Таблица"],
                        "col": row["Колонка"],
                        "status": row["Статус"],
                        "type": row["Тип PII (если Force)"] if row["Статус"] == "FORCE_PII" else None
                    })
                
                if updates:
                    success = backend.save_batch_settings(updates, current_db_config)
                    if success:
                        st.success("✅ Настройки успешно обновлены!")
                        import time
                        time.sleep(1)
                        st.rerun()
                    else:
                        st.error("Ошибка при сохранении.")
        else:
            st.warning("Нет подключения к БД или таблицы отсутствуют.")

# ==========================================
# ВКЛАДКА 3: ИСТОРИЯ (АУДИТ)
# ==========================================
with tab_history:
    st.header("📜 Журнал аудита безопасности")
    tab_app_log, tab_db_log = st.tabs(["App Logs (Приложение)", "DB Triggers (Ядро БД)"])
    
    with tab_app_log:
        logs = backend.get_audit_logs()
        if logs:
            df_logs = pd.DataFrame(logs, columns=["Дата", "Действие", "БД", "Детали"])
            st.dataframe(df_logs, use_container_width=True)
        else:
            st.info("Нет логов приложения.")

    with tab_db_log:
        st.write("Логи, записанные триггерами PostgreSQL (pii_guard.audit_log).")
        if st.button("🔄 Скачать логи с сервера БД"):
            conn = backend.get_connection(current_db_config)
            if not isinstance(conn, str):
                try:
                    df_db = pd.read_sql("SELECT event_time, db_user, table_name, operation, old_data, new_data FROM pii_guard.audit_log ORDER BY event_time DESC LIMIT 100", conn)
                    st.session_state["db_audit_logs"] = df_db
                except Exception as e:
                    st.error(f"Ошибка чтения логов БД: {e}")
                finally:
                    backend.close_connection(conn, current_db_config)
        if "db_audit_logs" in st.session_state:
            st.dataframe(st.session_state["db_audit_logs"], use_container_width=True)

st.divider()
st.caption("Postgres PII Guard Enterprise v2.0 | Курсовая работа | 2025")