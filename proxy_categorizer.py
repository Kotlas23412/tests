#!/usr/bin/env python3
"""
Упрощенный Proxy Checker
Парсит прокси из списков и проводит базовую валидацию
Для полной проверки используйте proxy_checker_xray.py
"""

import asyncio
import aiohttp
import json
import re
from typing import List, Dict, Optional
from dataclasses import dataclass, field
from collections import defaultdict
import urllib.parse


@dataclass
class ProxyInfo:
    """Информация о прокси"""
    url: str
    protocol: str
    host: str
    port: int
    uuid: Optional[str] = None
    sni: Optional[str] = None
    security: Optional[str] = None
    is_valid: bool = True
    error: Optional[str] = None


def parse_vless(url: str) -> Optional[ProxyInfo]:
    """Парсит VLESS URL"""
    if not url.startswith('vless://'):
        return None
    
    try:
        url = url[8:]  # Убираем vless://
        
        # Убираем фрагмент
        if '#' in url:
            url = url.split('#')[0]
        
        # UUID@HOST:PORT?params
        if '@' not in url:
            return ProxyInfo(url=f"vless://{url}", protocol='vless', 
                           host='', port=0, is_valid=False, 
                           error='Invalid format: missing @')
        
        uuid, rest = url.split('@', 1)
        
        # HOST:PORT?params
        if '?' in rest:
            address, params_str = rest.split('?', 1)
        else:
            address = rest
            params_str = ''
        
        if ':' not in address:
            return ProxyInfo(url=f"vless://{url}", protocol='vless',
                           host=address, port=0, is_valid=False,
                           error='Invalid format: missing port')
        
        host, port_str = address.rsplit(':', 1)
        try:
            port = int(port_str)
        except ValueError:
            return ProxyInfo(url=f"vless://{url}", protocol='vless',
                           host=host, port=0, is_valid=False,
                           error='Invalid port')
        
        # Парсим параметры
        params = {}
        if params_str:
            for param in params_str.split('&'):
                if '=' in param:
                    key, value = param.split('=', 1)
                    params[key] = urllib.parse.unquote(value)
        
        return ProxyInfo(
            url=f"vless://{url}",
            protocol='vless',
            host=host,
            port=port,
            uuid=uuid,
            sni=params.get('sni', host),
            security=params.get('security', 'none'),
            is_valid=True
        )
    
    except Exception as e:
        return ProxyInfo(url=url, protocol='vless', host='', port=0,
                       is_valid=False, error=str(e))


def parse_hysteria2(url: str) -> Optional[ProxyInfo]:
    """Парсит Hysteria2 URL"""
    if not url.startswith('hysteria2://') and not url.startswith('hy2://'):
        return None
    
    try:
        if url.startswith('hysteria2://'):
            url = url[12:]
        else:
            url = url[6:]
        
        # Убираем фрагмент
        if '#' in url:
            url = url.split('#')[0]
        
        # AUTH@HOST:PORT?params
        if '@' not in url:
            return ProxyInfo(url=url, protocol='hysteria2', host='', port=0,
                           is_valid=False, error='Invalid format: missing @')
        
        auth, rest = url.split('@', 1)
        
        if '?' in rest:
            address, params_str = rest.split('?', 1)
        else:
            address = rest
            params_str = ''
        
        if ':' not in address:
            return ProxyInfo(url=url, protocol='hysteria2', host=address,
                           port=0, is_valid=False, error='Invalid format: missing port')
        
        host, port_str = address.rsplit(':', 1)
        try:
            port = int(port_str)
        except ValueError:
            return ProxyInfo(url=url, protocol='hysteria2', host=host,
                           port=0, is_valid=False, error='Invalid port')
        
        params = {}
        if params_str:
            for param in params_str.split('&'):
                if '=' in param:
                    key, value = param.split('=', 1)
                    params[key] = urllib.parse.unquote(value)
        
        return ProxyInfo(
            url=url,
            protocol='hysteria2',
            host=host,
            port=port,
            uuid=auth,  # В hysteria2 это пароль, но сохраним как uuid
            sni=params.get('sni', host),
            security='tls',  # Hysteria2 всегда использует TLS
            is_valid=True
        )
    
    except Exception as e:
        return ProxyInfo(url=url, protocol='hysteria2', host='', port=0,
                       is_valid=False, error=str(e))


def categorize_proxies(proxies: List[str]) -> Dict[str, List[ProxyInfo]]:
    """Категоризирует и парсит прокси по протоколам"""
    
    categorized = {
        'vless': [],
        'vless_reality': [],
        'hysteria2': [],
        'unknown': [],
        'invalid': []
    }
    
    for proxy_url in proxies:
        proxy_url = proxy_url.strip()
        if not proxy_url or proxy_url.startswith('#'):
            continue
        
        # Определяем и парсим протокол
        if proxy_url.startswith('vless://'):
            info = parse_vless(proxy_url)
            if info:
                if not info.is_valid:
                    categorized['invalid'].append(info)
                elif info.security == 'reality':
                    categorized['vless_reality'].append(info)
                else:
                    categorized['vless'].append(info)
        
        elif proxy_url.startswith(('hysteria2://', 'hy2://')):
            info = parse_hysteria2(proxy_url)
            if info:
                if not info.is_valid:
                    categorized['invalid'].append(info)
                else:
                    categorized['hysteria2'].append(info)
        
        else:
            categorized['unknown'].append(
                ProxyInfo(url=proxy_url, protocol='unknown', host='', port=0,
                         is_valid=False, error='Unknown protocol')
            )
    
    return categorized


async def load_proxies_from_url(url: str) -> List[str]:
    """Загружает прокси с URL"""
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as response:
                if response.status == 200:
                    text = await response.text()
                    return text.split('\n')
    except Exception as e:
        print(f"❌ Ошибка загрузки: {e}")
    return []


def save_categorized_proxies(categorized: Dict[str, List[ProxyInfo]], 
                             output_dir: str = 'categorized_proxies'):
    """Сохраняет категоризированные прокси"""
    import os
    
    os.makedirs(output_dir, exist_ok=True)
    
    stats = {}
    
    for category, proxies in categorized.items():
        if not proxies:
            continue
        
        # Сохраняем URLs
        urls_file = os.path.join(output_dir, f'{category}.txt')
        with open(urls_file, 'w', encoding='utf-8') as f:
            for proxy in proxies:
                f.write(f"{proxy.url}\n")
        
        # Сохраняем детальную информацию
        info_file = os.path.join(output_dir, f'{category}_info.json')
        with open(info_file, 'w', encoding='utf-8') as f:
            info_list = []
            for proxy in proxies:
                info_dict = {
                    'url': proxy.url,
                    'protocol': proxy.protocol,
                    'host': proxy.host,
                    'port': proxy.port,
                    'uuid': proxy.uuid,
                    'sni': proxy.sni,
                    'security': proxy.security,
                    'is_valid': proxy.is_valid
                }
                if not proxy.is_valid:
                    info_dict['error'] = proxy.error
                info_list.append(info_dict)
            
            json.dump(info_list, f, indent=2, ensure_ascii=False)
        
        stats[category] = len(proxies)
        print(f"✅ {category}: {len(proxies)} прокси")
        print(f"   📁 {urls_file}")
        print(f"   📊 {info_file}")
    
    return stats


async def main():
    """Главная функция"""
    print("=" * 70)
    print("🔍 PROXY CATEGORIZER & VALIDATOR")
    print("=" * 70)
    print()
    
    # Источники прокси
    print("📥 Загрузка прокси...")
    print()
    print("Введите URL или путь к файлу с прокси:")
    print("(Оставьте пустым для использования примера)")
    
    source = input("> ").strip()
    
    if source:
        if source.startswith('http://') or source.startswith('https://'):
            proxies = await load_proxies_from_url(source)
        else:
            # Читаем из локального файла
            try:
                with open(source, 'r', encoding='utf-8') as f:
                    proxies = f.readlines()
            except Exception as e:
                print(f"❌ Ошибка чтения файла: {e}")
                return
    else:
        # Пример
        proxies = [
            "vless://8b8f4dfb-cd48-4dab-bb75-b304971176cd@45.95.233.85:61873?security=reality&encryption=none&pbk=wEU32qHhiQq-FDYUvuEl7_HAM6r5nDh6M4F8WGnEhjE&headerType=none&fp=chrome&type=tcp&sni=yandex.ru&sid=34d8e80d8fa40501",
            "vless://test-uuid@example.com:443?security=tls&sni=example.com",
            "hysteria2://password@server.com:443?sni=server.com",
        ]
    
    if not proxies:
        print("❌ Нет прокси для обработки")
        return
    
    print(f"✅ Загружено {len(proxies)} строк")
    print()
    
    # Категоризируем
    print("🔍 Анализ и категоризация...")
    categorized = categorize_proxies(proxies)
    
    # Выводим статистику
    print()
    print("=" * 70)
    print("📊 РЕЗУЛЬТАТЫ АНАЛИЗА:")
    print("=" * 70)
    
    total_valid = sum(len(categorized[cat]) for cat in ['vless', 'vless_reality', 'hysteria2'])
    total_invalid = len(categorized['invalid'])
    total_unknown = len(categorized['unknown'])
    
    print(f"\n✅ Валидные прокси: {total_valid}")
    print(f"   ├─ VLESS: {len(categorized['vless'])}")
    print(f"   ├─ VLESS + Reality: {len(categorized['vless_reality'])}")
    print(f"   └─ Hysteria2: {len(categorized['hysteria2'])}")
    
    if total_invalid > 0:
        print(f"\n❌ Невалидные: {total_invalid}")
        # Показываем примеры ошибок
        error_types = defaultdict(int)
        for proxy in categorized['invalid'][:10]:
            error_types[proxy.error] += 1
        print("   Типы ошибок:")
        for error, count in error_types.items():
            print(f"   - {error}: {count}")
    
    if total_unknown > 0:
        print(f"\n⚠️  Неизвестный протокол: {total_unknown}")
    
    # Сохраняем результаты
    print()
    print("💾 Сохранение результатов...")
    print()
    save_categorized_proxies(categorized)
    
    print()
    print("=" * 70)
    print("✅ ГОТОВО!")
    print("=" * 70)
    print()
    print("📁 Результаты сохранены в папке 'categorized_proxies/'")
    print()
    print("🚀 Для полноценной проверки на работоспособность используйте:")
    print("   python3 proxy_checker_xray.py")
    print()


if __name__ == '__main__':
    asyncio.run(main())
