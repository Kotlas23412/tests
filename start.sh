#!/bin/bash
# Скрипт быстрого запуска Proxy Checker

set -e

echo "=========================================="
echo "🚀 Proxy Checker - Быстрый старт"
echo "=========================================="
echo ""

# Проверка Python
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 не найден. Установите Python 3.8+"
    exit 1
fi

echo "✅ Python $(python3 --version)"

# Установка зависимостей
if [ ! -d "venv" ]; then
    echo "📦 Создаю виртуальное окружение..."
    python3 -m venv venv
fi

echo "📦 Активирую виртуальное окружение..."
source venv/bin/activate

echo "📦 Устанавливаю зависимости..."
pip install -q -r requirements.txt

# Проверка xray-core
if ! command -v xray &> /dev/null; then
    echo ""
    echo "⚠️  xray-core не найден!"
    echo ""
    echo "Варианты:"
    echo "1. Использовать простой категоризатор (без проверки работоспособности)"
    echo "2. Установить xray-core (требуется для полной проверки)"
    echo ""
    read -p "Выберите вариант (1/2): " choice
    
    if [ "$choice" == "1" ]; then
        echo ""
        echo "🔍 Запуск простого категоризатора..."
        python3 proxy_categorizer.py
        exit 0
    else
        echo ""
        echo "📥 Скачиваю xray-core..."
        
        # Определяем архитектуру
        ARCH=$(uname -m)
        if [ "$ARCH" == "x86_64" ]; then
            XRAY_FILE="Xray-linux-64.zip"
        elif [ "$ARCH" == "aarch64" ]; then
            XRAY_FILE="Xray-linux-arm64-v8a.zip"
        else
            echo "❌ Неподдерживаемая архитектура: $ARCH"
            exit 1
        fi
        
        wget -q https://github.com/XTLS/Xray-core/releases/latest/download/$XRAY_FILE
        unzip -q $XRAY_FILE
        chmod +x xray
        
        echo "✅ xray-core скачан"
        echo ""
        echo "Установить глобально? (требуется sudo)"
        read -p "(y/n): " install_global
        
        if [ "$install_global" == "y" ]; then
            sudo mv xray /usr/local/bin/
            echo "✅ xray установлен в /usr/local/bin/"
        else
            echo "✅ xray доступен локально (./xray)"
        fi
        
        rm $XRAY_FILE
    fi
fi

echo ""
echo "✅ xray-core найден: $(xray version | head -1)"

# Проверка файла с прокси
if [ ! -f "proxies.txt" ]; then
    echo ""
    echo "⚠️  Файл proxies.txt не найден!"
    echo ""
    echo "Создайте файл proxies.txt с вашими прокси (по одному на строку)"
    echo "Или используйте proxies_example.txt как шаблон:"
    echo "  cp proxies_example.txt proxies.txt"
    echo ""
    exit 1
fi

# Запуск проверки
echo ""
echo "🔍 Запуск проверки прокси..."
echo ""
python3 proxy_checker_xray.py

echo ""
echo "=========================================="
echo "✅ Готово!"
echo "=========================================="
echo ""
echo "📁 Результаты в папке: working_proxies/"
echo ""
