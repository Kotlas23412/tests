#!/usr/bin/env python3
"""
Продвинутый Proxy Checker с xray-core
Реальная проверка VLESS/Reality/Hysteria2 через xray-core
"""

import asyncio
import aiohttp
import json
import subprocess
import tempfile
import os
import time
from typing import List, Dict, Tuple, Optional
from dataclasses import dataclass
from pathlib import Path
import random


@dataclass
class ProxyResult:
    """Результат проверки прокси"""
    url: str
    protocol: str
    host: str
    port: int
    success_count: int = 0
    fail_count: int = 0
    avg_latency: float = 0.0
    working_domains: List[str] = None
    
    def __post_init__(self):
        if self.working_domains is None:
            self.working_domains = []
    
    @property
    def success_rate(self) -> float:
        total = self.success_count + self.fail_count
        return (self.success_count / total * 100) if total > 0 else 0
    
    @property
    def score(self) -> float:
        """Комплексная оценка: 70% успешность + 30% скорость"""
        if self.avg_latency == 0:
            speed_score = 0
        else:
            # 0-1сек = 100, 1-3сек = 70, 3-5сек = 40, >5сек = 0
            if self.avg_latency < 1:
                speed_score = 100
            elif self.avg_latency < 3:
                speed_score = 100 - (self.avg_latency - 1) * 15
            elif self.avg_latency < 5:
                speed_score = 70 - (self.avg_latency - 3) * 15
            else:
                speed_score = max(0, 40 - (self.avg_latency - 5) * 8)
        
        return (self.success_rate * 0.7) + (speed_score * 0.3)


def parse_vless_url(url: str) -> Optional[Dict]:
    """Парсит VLESS URL в конфигурацию xray"""
    import urllib.parse
    
    if not url.startswith('vless://'):
        return None
    
    try:
        # vless://UUID@HOST:PORT?params#fragment
        url = url[8:]  # Убираем vless://
        
        # Разделяем UUID и остальное
        if '@' not in url:
            return None
        
        uuid, rest = url.split('@', 1)
        
        # Убираем fragment если есть
        if '#' in rest:
            rest = rest.split('#')[0]
        
        # Разделяем адрес:порт и параметры
        if '?' in rest:
            address, params_str = rest.split('?', 1)
        else:
            address = rest
            params_str = ''
        
        if ':' not in address:
            return None
        
        host, port = address.rsplit(':', 1)
        port = int(port)
        
        # Парсим параметры
        params = {}
        if params_str:
            for param in params_str.split('&'):
                if '=' in param:
                    key, value = param.split('=', 1)
                    params[key] = urllib.parse.unquote(value)
        
        return {
            'uuid': uuid,
            'host': host,
            'port': port,
            'security': params.get('security', 'none'),
            'encryption': params.get('encryption', 'none'),
            'flow': params.get('flow', ''),
            'sni': params.get('sni', host),
            'fp': params.get('fp', 'chrome'),
            'pbk': params.get('pbk', ''),
            'sid': params.get('sid', ''),
            'type': params.get('type', 'tcp'),
            'headerType': params.get('headerType', 'none'),
            'alpn': params.get('alpn', '').split(',') if params.get('alpn') else []
        }
    except Exception as e:
        print(f"Ошибка парсинга VLESS: {e}")
        return None

def parse_hysteria2_url(url: str) -> Optional[Dict]:
    """Парсит Hysteria2 URL в конфигурацию xray"""
    import urllib.parse
    if not (url.startswith('hysteria2://') or url.startswith('hy2://')):
        return None
    try:
        url_clean = url.replace('hysteria2://', '').replace('hy2://', '')
        if '@' not in url_clean: return None
        auth, rest = url_clean.split('@', 1)
        if '?' in rest:
            address, params_str = rest.split('?', 1)
        else:
            address, params_str = rest, ''
        host, port = address.rsplit(':', 1)
        params = {k: v[0] for k, v in urllib.parse.parse_qs(params_str).items()}
        return {
            'auth': auth,
            'host': host,
            'port': int(port),
            'sni': params.get('sni', host),
            'alpn': params.get('alpn', 'h3').split(',')
        }
    except: return None

def create_xray_config(proxy_info: Dict, socks_port: int = 10808, http_port: int = 10809) -> Dict:
    """Создает конфигурацию xray-core для прокси"""
    
    config = {
        "log": {
            "loglevel": "warning"
        },
        "inbounds": [
            {
                "port": socks_port,
                "protocol": "socks",
                "settings": {
                    "udp": True
                }
            },
            {
                "port": http_port,
                "protocol": "http"
            }
        ],
        "outbounds": [
            {
                "protocol": "vless",
                "settings": {
                    "vnext": [
                        {
                            "address": proxy_info['host'],
                            "port": proxy_info['port'],
                            "users": [
                                {
                                    "id": proxy_info['uuid'],
                                    "encryption": proxy_info.get('encryption', 'none'),
                                    "flow": proxy_info.get('flow', '')
                                }
                            ]
                        }
                    ]
                },
                "streamSettings": {
                    "network": proxy_info.get('type', 'tcp'),
                    "security": proxy_info.get('security', 'none')
                }
            }
        ]
    }
    
    # Добавляем настройки Reality
    if proxy_info.get('security') == 'reality':
        config['outbounds'][0]['streamSettings']['realitySettings'] = {
            "serverName": proxy_info.get('sni', proxy_info['host']),
            "fingerprint": proxy_info.get('fp', 'chrome'),
            "shortId": proxy_info.get('sid', ''),
            "publicKey": proxy_info.get('pbk', '')
        }
    if proxy_info.get('auth') and protocol == 'hysteria2': # Нужно передать protocol в функцию или определять внутри    
    # Добавляем настройки TLS
    elif proxy_info.get('security') == 'tls':
        config['outbounds'][0]['streamSettings']['tlsSettings'] = {
            "serverName": proxy_info.get('sni', proxy_info['host']),
            "fingerprint": proxy_info.get('fp', 'chrome'),
            "alpn": proxy_info.get('alpn', [])
        }
    
    return config


async def test_proxy_through_xray(xray_path: str, config: Dict, 
                                   test_url: str, timeout: int = 15) -> Tuple[bool, float]:
    """
    Тестирует прокси через xray-core
    Возвращает (успех, задержка в секундах)
    """
    # Создаем временный конфиг
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(config, f)
        config_path = f.name
    
    xray_process = None
    try:
        # Запускаем xray
        xray_process = subprocess.Popen(
            [xray_path, '-config', config_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        
        # Даем xray время на запуск
        await asyncio.sleep(2)
        
        # Проверяем работоспособность через прокси
        http_port = config['inbounds'][1]['port']
        proxy_url = f'http://127.0.0.1:{http_port}'
        
        start_time = time.time()
        
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(
                    test_url,
                    proxy=proxy_url,
                    timeout=aiohttp.ClientTimeout(total=timeout),
                    ssl=False
                ) as response:
                    latency = time.time() - start_time
                    
                    if 200 <= response.status < 500:
                        return True, latency
                    return False, latency
                    
            except asyncio.TimeoutError:
                return False, timeout
            except Exception as e:
                return False, timeout
    
    finally:
        # Останавливаем xray
        if xray_process:
            xray_process.terminate()
            try:
                xray_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                xray_process.kill()
        
        # Удаляем временный конфиг
        try:
            os.unlink(config_path)
        except:
            pass


async def check_proxy(proxy_url: str, test_domains: List[str], 
                     xray_path: str, max_domains: int = 10) -> Optional[ProxyResult]:
    """Проверяет один прокси на нескольких доменах"""
    
    # Парсим прокси
    if proxy_url.startswith('vless://'):
        protocol = 'vless'
        proxy_info = parse_vless_url(proxy_url)
    elif proxy_url.startswith('hysteria2://') or proxy_url.startswith('hy2://'):
        protocol = 'hysteria2'
        proxy_info = parse_hysteria2_url(proxy_url)
        # TODO: добавить парсинг Hysteria2
        print(f"⚠️  Hysteria2 пока не поддерживается")
        return None
    else:
        print(f"❌ Неизвестный протокол: {proxy_url[:20]}...")
        return None
    
    if not proxy_info:
        print(f"❌ Не удалось распарсить прокси")
        return None
    
    # Создаем результат
    result = ProxyResult(
        url=proxy_url,
        protocol=protocol,
        host=proxy_info['host'],
        port=proxy_info['port']
    )
    
    # Выбираем случайные домены для теста
    test_sample = random.sample(test_domains, min(max_domains, len(test_domains)))
    
    # Создаем конфиг xray
    xray_config = create_xray_config(proxy_info)
    
    latencies = []
    
    # Тестируем на каждом домене
    for domain in test_sample:
        test_url = f"https://{domain}"
        success, latency = await test_proxy_through_xray(
            xray_path, xray_config, test_url, timeout=15
        )
        
        if success:
            result.success_count += 1
            result.working_domains.append(domain)
            latencies.append(latency)
        else:
            result.fail_count += 1
    
    # Вычисляем среднюю задержку
    if latencies:
        result.avg_latency = sum(latencies) / len(latencies)
    
    return result


async def batch_check_proxies(proxy_list: List[str], test_domains: List[str],
                              xray_path: str, max_concurrent: int = 5) -> List[ProxyResult]:
    """Проверяет список прокси параллельно"""
    
    results = []
    semaphore = asyncio.Semaphore(max_concurrent)
    
    async def check_with_semaphore(proxy_url: str, index: int):
        async with semaphore:
            print(f"[{index + 1}/{len(proxy_list)}] Проверка {proxy_url[:50]}...")
            result = await check_proxy(proxy_url, test_domains, xray_path)
            if result:
                print(f"  ✓ {result.success_rate:.1f}% успех, "
                      f"{result.avg_latency:.2f}с задержка, "
                      f"оценка: {result.score:.1f}")
            return result
    
    tasks = [check_with_semaphore(proxy, i) for i, proxy in enumerate(proxy_list)]
    results = await asyncio.gather(*tasks)
    
    return [r for r in results if r is not None]


def save_results_by_protocol(results: List[ProxyResult], output_dir: str = 'output'):
    """Сохраняет результаты, разбитые по протоколам"""
    
    os.makedirs(output_dir, exist_ok=True)
    
    # Группируем по протоколам
    by_protocol = {}
    for result in results:
        if result.protocol not in by_protocol:
            by_protocol[result.protocol] = []
        by_protocol[result.protocol].append(result)
    
    # Сохраняем каждый протокол
    for protocol, proto_results in by_protocol.items():
        # Сортируем по оценке
        sorted_results = sorted(proto_results, key=lambda x: x.score, reverse=True)
        
        # Топ-500
        top_500 = sorted_results[:500]
        
        # Сохраняем URLs
        urls_file = os.path.join(output_dir, f'{protocol}_top500.txt')
        with open(urls_file, 'w', encoding='utf-8') as f:
            for r in top_500:
                f.write(f"{r.url}\n")
        
        # Сохраняем статистику
        stats_file = os.path.join(output_dir, f'{protocol}_stats.json')
        with open(stats_file, 'w', encoding='utf-8') as f:
            stats = [
                {
                    'url': r.url,
                    'host': r.host,
                    'port': r.port,
                    'success_rate': round(r.success_rate, 2),
                    'avg_latency': round(r.avg_latency, 3),
                    'score': round(r.score, 2),
                    'working_domains_count': len(r.working_domains)
                }
                for r in top_500
            ]
            json.dump(stats, f, indent=2, ensure_ascii=False)
        
        print(f"\n✅ {protocol.upper()}:")
        print(f"   📁 {urls_file} - {len(top_500)} прокси")
        print(f"   📊 {stats_file} - детальная статистика")


async def load_from_url(url: str) -> List[str]:
    """Загружает список строк с URL"""
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as response:
                if response.status == 200:
                    text = await response.text()
                    return [line.strip() for line in text.split('\n') 
                           if line.strip() and not line.startswith('#')]
    except Exception as e:
        print(f"❌ Ошибка загрузки {url}: {e}")
    return []


async def main():
    """Главная функция"""
    print("=" * 70)
    print("🚀 PROXY CHECKER для РФ с xray-core")
    print("=" * 70)
    
    # Проверяем наличие xray-core
    xray_path = 'xray'  # или укажите полный путь
    try:
        result = subprocess.run([xray_path, 'version'], 
                              capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            print(f"✅ Найден xray-core: {result.stdout.split()[1]}")
        else:
            print("❌ xray-core не найден. Установите с https://github.com/XTLS/Xray-core")
            return
    except Exception as e:
        print(f"❌ xray-core не найден: {e}")
        print("   Установите: https://github.com/XTLS/Xray-core/releases")
        return
    
    # Загружаем домены для тестирования
    print("\n📥 Загрузка тестовых доменов...")
    SNI_URL = 'https://raw.githubusercontent.com/Kotlas23412/proxy-checker/refs/heads/main/sni.txt'
    test_domains = await load_from_url(SNI_URL)
    
    if not test_domains:
        print("⚠️  Используем стандартный набор доменов")
        test_domains = [
            'yandex.ru', 'mail.ru', 'vk.ru', 'ok.ru', 'sberbank.ru',
            'gosuslugi.ru', 'rzd.ru', 'ozon.ru', 'wildberries.ru', 'avito.ru'
        ]
    
    print(f"✅ Загружено {len(test_domains)} доменов")
    
    # Загружаем прокси
    print("\n📥 Загрузка прокси...")
    filename = 'proxies.txt'
    initial_lines = []

    if os.path.exists(filename):
        with open(filename, 'r', encoding='utf-8') as f:
            initial_lines = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        print(f"✅ Прочитано {len(initial_lines)} строк из {filename}")
    else:
        print(f"❌ Файл {filename} не найден!")
        return

    proxies = []
    for line in initial_lines:
        if line.startswith('http'):
            print(f"🌐 Загрузка прокси по ссылке: {line[:60]}...")
            fetched = await load_from_url(line)
            proxies.extend(fetched)
        else:
            proxies.append(line)

    # Удаляем дубликаты
    proxies = list(set(proxies))
    print(f"✅ Итого получено {len(proxies)} уникальных прокси")
    
    # Запускаем проверку
    print(f"\n🔍 Начинаю проверку...")
    print(f"⚙️  Параметры:")
    print(f"   - Прокси: {len(proxies)}")
    print(f"   - Доменов на прокси: 10")
    print(f"   - Параллельных проверок: 5")
    print()
    
    results = await batch_check_proxies(proxies, test_domains, xray_path, max_concurrent=5)
    
    # Фильтруем рабочие (>50% успешности)
    working = [r for r in results if r.success_rate >= 50]
    
    print(f"\n" + "=" * 70)
    print(f"📊 РЕЗУЛЬТАТЫ:")
    print(f"   Всего проверено: {len(results)}")
    print(f"   Рабочих (>50%): {len(working)}")
    
    if working:
        print(f"\n💾 Сохранение результатов...")
        save_results_by_protocol(working, output_dir='working_proxies')
        print(f"\n✅ Готово! Проверьте папку 'working_proxies'")
    else:
        print(f"\n⚠️  Не найдено рабочих прокси")
    
    print("=" * 70)


if __name__ == '__main__':
    asyncio.run(main())
