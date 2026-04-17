# 🚀 Быстрый старт

## 1️⃣ Простой способ (Linux/Mac)

```bash
# 1. Скопируйте все файлы в папку
cd proxy-checker

# 2. Создайте файл с вашими прокси
nano proxies.txt
# Вставьте прокси (по одному на строку)

# 3. Запустите автоматический скрипт
./start.sh
```

Готово! Результаты в папке `working_proxies/`

---

## 2️⃣ Ручная установка

### Шаг 1: Установите Python зависимости
```bash
pip install aiohttp
```

### Шаг 2: Установите xray-core

**Linux:**
```bash
wget https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip
unzip Xray-linux-64.zip
chmod +x xray
sudo mv xray /usr/local/bin/
```

**Mac:**
```bash
brew install xray
```

**Windows:**
- Скачайте https://github.com/XTLS/Xray-core/releases
- Распакуйте xray.exe
- Добавьте в PATH

### Шаг 3: Запустите проверку

**Простая категоризация (без проверки):**
```bash
python3 proxy_categorizer.py
```

**Полная проверка (требуется xray):**
```bash
python3 proxy_checker_xray.py
```

---

## 3️⃣ Docker (самый простой)

```bash
# 1. Создайте proxies.txt с вашими прокси

# 2. Запустите контейнер
docker-compose up --build

# 3. Результаты в working_proxies/
```

---

## 📋 Формат прокси

### VLESS + Reality:
```
vless://UUID@SERVER:PORT?security=reality&encryption=none&pbk=PUBLIC_KEY&fp=chrome&type=tcp&sni=yandex.ru&sid=SHORT_ID
```

### VLESS + TLS:
```
vless://UUID@SERVER:PORT?security=tls&encryption=none&type=tcp&sni=domain.com&fp=chrome
```

### Hysteria2:
```
hysteria2://PASSWORD@SERVER:PORT?sni=domain.com&alpn=h3
```

---

## 📊 Результаты

После проверки получите:

```
working_proxies/
├── vless_top500.txt          # Топ-500 VLESS прокси
├── vless_stats.json          # Подробная статистика
├── vless_reality_top500.txt  # Топ-500 VLESS+Reality
└── hysteria2_top500.txt      # Топ-500 Hysteria2
```

---

## ⚡ Быстрые команды

### Проверить один прокси:
```bash
python3 -c "
from proxy_checker_xray import check_proxy, load_from_url
import asyncio

async def test():
    domains = ['yandex.ru', 'mail.ru', 'vk.ru']
    proxy = 'vless://...'
    result = await check_proxy(proxy, domains, 'xray')
    print(f'Успех: {result.success_rate}%')

asyncio.run(test())
"
```

### Загрузить прокси с GitHub:
```python
# В proxy_checker_xray.py измените:
proxies = await load_from_url('https://raw.githubusercontent.com/USER/REPO/main/proxies.txt')
```

### Изменить параметры проверки:
```python
# В proxy_checker_xray.py найдите:
max_domains = 10        # Количество тестовых доменов
max_concurrent = 5      # Параллельных проверок
timeout = 15            # Таймаут в секундах
```

---

## ❗ Важно

1. **Запускайте из РФ** - проверка из США даст неточные результаты
2. **Не на GitHub Actions** - сервера в США, результаты будут искажены
3. **VPS в РФ** - идеальный вариант для регулярной проверки
4. **Локально в РФ** - тоже подходит

---

## 🐛 Проблемы?

### "xray not found"
```bash
which xray  # Проверьте путь
# Или укажите полный путь в скрипте
```

### "Permission denied"
```bash
chmod +x start.sh
chmod +x xray
```

### Все прокси не работают
- Проверьте формат URL
- Увеличьте timeout до 30
- Попробуйте другие прокси

---

## 📖 Полная документация

См. `README.md` для подробностей
