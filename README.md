# 🚀 Proxy Checker для РФ

Автоматическая проверка работоспособности VLESS/Reality/Hysteria2 прокси для российских сайтов.

## 📋 Особенности

- ✅ Поддержка протоколов: VLESS, VLESS+Reality, Hysteria2
- ✅ Проверка на реальных российских сайтах (Яндекс, Mail.ru, VK, Госуслуги и др.)
- ✅ Автоматическая сортировка по качеству (скорость + стабильность)
- ✅ Сохранение топ-500 лучших прокси для каждого протокола
- ✅ Параллельная проверка для ускорения
- ✅ Интеграция с xray-core для точного тестирования

## 📦 Установка

### 1. Установите Python 3.8+

```bash
python3 --version  # Проверьте версию
```

### 2. Установите зависимости

```bash
pip install -r requirements.txt
```

### 3. Установите xray-core

#### Linux/Mac:
```bash
# Скачайте с GitHub
wget https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip
unzip Xray-linux-64.zip
chmod +x xray
sudo mv xray /usr/local/bin/

# Проверьте установку
xray version
```

#### Windows:
1. Скачайте с https://github.com/XTLS/Xray-core/releases
2. Распакуйте xray.exe
3. Добавьте путь к xray.exe в PATH или укажите полный путь в скрипте

## 🎯 Использование

### Вариант 1: С локальными файлами

Создайте файлы с прокси:
- `vless_proxies.txt` - VLESS прокси
- `hysteria2_proxies.txt` - Hysteria2 прокси

Формат (по одному на строку):
```
vless://UUID@HOST:PORT?параметры
hysteria2://AUTH@HOST:PORT?параметры
```

Запустите:
```bash
python3 proxy_checker_xray.py
```

### Вариант 2: С GitHub

Измените в скрипте URL на ваш репозиторий:
```python
PROXY_URL = 'https://raw.githubusercontent.com/YOUR_USER/YOUR_REPO/main/proxies.txt'
```

### Вариант 3: Быстрая проверка одного прокси

```bash
python3 -c "
import asyncio
from proxy_checker_xray import check_proxy, load_from_url

async def test():
    domains = await load_from_url('https://raw.githubusercontent.com/Kotlas23412/proxy-checker/refs/heads/main/sni.txt')
    proxy = 'vless://your-proxy-url-here'
    result = await check_proxy(proxy, domains, 'xray')
    print(f'Успешность: {result.success_rate}%')
    print(f'Задержка: {result.avg_latency}с')

asyncio.run(test())
"
```

## 📊 Результаты

После проверки создается папка `working_proxies/` с файлами:

```
working_proxies/
├── vless_top500.txt           # Топ-500 VLESS прокси
├── vless_stats.json           # Детальная статистика VLESS
├── hysteria2_top500.txt       # Топ-500 Hysteria2 прокси
└── hysteria2_stats.json       # Детальная статистика Hysteria2
```

### Формат stats.json:

```json
[
  {
    "url": "vless://...",
    "host": "45.95.233.85",
    "port": 61873,
    "success_rate": 90.0,
    "avg_latency": 1.234,
    "score": 78.5,
    "working_domains_count": 9
  }
]
```

## ⚙️ Настройки

В скрипте `proxy_checker_xray.py` можно изменить:

```python
# Количество доменов для теста на каждый прокси
max_domains = 10  # по умолчанию 10

# Количество параллельных проверок
max_concurrent = 5  # по умолчанию 5

# Timeout для каждой проверки (секунды)
timeout = 15  # по умолчанию 15

# Порог для "рабочих" прокси
success_threshold = 50  # минимум 50% успешности
```

## 🎯 Алгоритм оценки

Каждый прокси получает оценку (score) от 0 до 100:

```
Score = (Success_Rate × 0.7) + (Speed_Score × 0.3)

где Speed_Score:
  < 1 сек   = 100
  1-3 сек   = 70-100
  3-5 сек   = 40-70
  > 5 сек   = 0-40
```

## 📝 Примеры прокси

### VLESS + Reality:
```
vless://UUID@HOST:PORT?security=reality&encryption=none&pbk=PUBLIC_KEY&headerType=none&fp=chrome&type=tcp&sni=yandex.ru&sid=SHORT_ID
```

### VLESS + TLS:
```
vless://UUID@HOST:PORT?security=tls&encryption=none&type=tcp&sni=example.com&fp=chrome
```

### Hysteria2:
```
hysteria2://PASSWORD@HOST:PORT?sni=example.com&alpn=h3
```

## 🔧 Troubleshooting

### xray-core не найден
```bash
# Проверьте установку
which xray

# Или укажите полный путь в скрипте
xray_path = '/path/to/xray'
```

### Ошибка импорта aiohttp
```bash
pip install --upgrade aiohttp
```

### Все прокси не работают
1. Проверьте формат URL прокси
2. Убедитесь что прокси не заблокированы в вашей сети
3. Попробуйте увеличить timeout до 30 секунд
4. Проверьте работу одного прокси вручную через xray-core

### GitHub Actions (проверка на серверах в США)

Не рекомендуется запускать проверку на серверах GitHub (они в США).
Лучше запустить на:
- VPS в РФ или близких странах
- Локальном компьютере в РФ
- VPS в Казахстане, Беларуси, Турции и т.д.

## 🌍 Тестовые домены

Скрипт использует список из 500+ российских доменов:
- Государственные: gosuslugi.ru, kremlin.ru, duma.gov.ru
- Банки: sberbank.ru, alfabank.ru, vtb.ru
- Соцсети: vk.ru, ok.ru, dzen.ru
- Маркетплейсы: ozon.ru, wildberries.ru, avito.ru
- И многие другие

Полный список: https://github.com/Kotlas23412/proxy-checker/blob/main/sni.txt

## 📈 Рекомендации

1. **Запускайте из РФ** - проверка из США даст искаженные результаты
2. **Не более 100 прокси одновременно** - иначе проверка займет много времени
3. **Проверяйте регулярно** - прокси могут перестать работать
4. **Сохраняйте топ-100** - обычно достаточно лучших прокси
5. **Комбинируйте протоколы** - разные протоколы для разных сценариев

## 🤝 Contributing

Pull requests приветствуются! Особенно:
- Поддержка других протоколов (Shadowsocks, Trojan)
- Улучшение алгоритма оценки
- Оптимизация скорости проверки
- Добавление GUI

## 📄 License

MIT License - используйте свободно

## ⚠️ Disclaimer

Этот инструмент предназначен для тестирования собственных прокси-серверов.
Использование чужих прокси без разрешения может быть незаконным.
