FROM python:3.10-slim

# Установка зависимостей
RUN apt-get update && apt-get install -y \
    wget \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Рабочая директория
WORKDIR /app

# Копируем файлы
COPY requirements.txt .
COPY *.py .
COPY *.md .

# Устанавливаем Python зависимости
RUN pip install --no-cache-dir -r requirements.txt

# Скачиваем и устанавливаем xray-core
RUN wget https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip && \
    unzip Xray-linux-64.zip && \
    chmod +x xray && \
    mv xray /usr/local/bin/ && \
    rm Xray-linux-64.zip

# Создаем директорию для результатов
RUN mkdir -p /app/working_proxies

# Точка входа
CMD ["python3", "proxy_checker_xray.py"]
