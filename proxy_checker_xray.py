#!/usr/bin/env python3
"""
Продвинутый Proxy Checker с xray-core
Поддержка VLESS и Hysteria2
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
        if self.avg_latency == 0:
            speed_score = 0
        else:
            if self.avg_latency < 1: speed_score = 100
            elif self.avg_latency < 3: speed_score = 100 - (self.avg_latency - 1) * 15
            elif self.avg_latency < 5: speed_score = 70 - (self.avg_latency - 3) * 15
            else: speed_score = max(0, 40 - (self.avg_latency - 5) * 8)
        return (self.success_rate * 0.7) + (speed_score * 0.3)


def parse_vless_url(url: str) -> Optional[Dict]:
    import urllib.parse
    if not url.startswith('vless://'): return None
    try:
        url_part = url[8:]
        if '@' not in url_part: return None
        uuid, rest = url_part.split('@', 1)
        if '#' in rest: rest = rest.split('#')[0]
        if '?' in rest: address, params_str = rest.split('?', 1)
        else: address, params_str = rest, ''
        host, port = address.rsplit(':', 1)
        params = {k: v[0] for k, v in urllib.parse.parse_qs(params_str).items()}
        return {
            'uuid': uuid, 'host': host, 'port': int(port),
            'security': params.get('security', 'none'),
            'sni': params.get('sni', host),
            'fp': params.get('fp', 'chrome'),
            'pbk': params.get('pbk', ''),
            'sid': params.get('sid', ''),
            'type': params.get('type', 'tcp'),
            'flow': params.get('flow', ''),
            'alpn': params.get('alpn', '').split(',') if params.get('alpn') else []
        }
    except: return None


def parse_hysteria2_url(url: str) -> Optional[Dict]:
    import urllib.parse
    if not (url.startswith('hysteria2://') or url.startswith('hy2://')): return None
    try:
        url_clean = url.replace('hysteria2://', '').replace('hy2://', '')
        if '@' not in url_clean: return None
        auth, rest = url_clean.split('@', 1)
        if '?' in rest: address, params_str = rest.split('?', 1)
        else: address, params_str = rest, ''
        host, port = address.rsplit(':', 1)
        params = {k: v[0] for k, v in urllib.parse.parse_qs(params_str).items()}
        return {
            'auth': auth, 'host': host, 'port': int(port),
            'sni': params.get('sni', host),
            'alpn': params.get('alpn', 'h3').split(',')
        }
    except: return None


def create_xray_config(proxy_info: Dict, protocol: str, socks_port: int = 10808, http_port: int = 10809) -> Dict:
    config = {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {"port": socks_port, "protocol": "socks", "settings": {"udp": True}},
            {"port": http_port, "protocol": "http"}
        ],
        "outbounds": []
    }

    if protocol == 'vless':
        outbound = {
            "protocol": "vless",
            "settings": {
                "vnext": [{"address": proxy_info['host'], "port": proxy_info['port'],
                           "users": [{"id": proxy_info['uuid'], "encryption": "none", "flow": proxy_info.get('flow', '')}]}]
            },
            "streamSettings": {
                "network": proxy_info.get('type', 'tcp'),
                "security": proxy_info.get('security', 'none')
            }
        }
        if proxy_info.get('security') == 'reality':
            outbound['streamSettings']['realitySettings'] = {
                "serverName": proxy_info['sni'], "fingerprint": proxy_info['fp'],
                "shortId": proxy_info['sid'], "publicKey": proxy_info['pbk']
            }
        elif proxy_info.get('security') == 'tls':
            outbound['streamSettings']['tlsSettings'] = {
                "serverName": proxy_info['sni'], "fingerprint": proxy_info['fp'], "alpn": proxy_info['alpn']
            }
        config['outbounds'].append(outbound)

    elif protocol == 'hysteria2':
        outbound = {
            "protocol": "hysteria2",
            "settings": {
                "servers": [{"address": proxy_info['host'], "port": proxy_info['port'], "auth": proxy_info['auth']}]
            },
            "streamSettings": {
                "network": "udp",
                "security": "tls",
                "tlsSettings": {"serverName": proxy_info['sni'], "alpn": proxy_info['alpn']}
            }
        }
        config['outbounds'].append(outbound)

    return config


async def test_proxy_through_xray(xray_path: str, config: Dict, test_url: str, timeout: int = 15) -> Tuple[bool, float]:
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(config, f)
        config_path = f.name
    
    xray_process = None
    try:
        xray_process = subprocess.Popen([xray_path, '-config', config_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        await asyncio.sleep(2)
        
        http_port = config['inbounds'][1]['port']
        proxy_url = f'http://127.0.0.1:{http_port}'
        start_time = time.time()
        
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(test_url, proxy=proxy_url, timeout=aiohttp.ClientTimeout(total=timeout), ssl=False) as response:
                    if 200 <= response.status < 500:
                        return True, time.time() - start_time
            except: pass
        return False, timeout
    finally:
        if xray_process:
            xray_process.terminate()
            xray_process.wait()
        if os.path.exists(config_path): os.unlink(config_path)


async def check_proxy(proxy_url: str, test_domains: List[str], xray_path: str, max_domains: int = 5) -> Optional[ProxyResult]:
    if proxy_url.startswith('vless://'):
        protocol = 'vless'
        proxy_info = parse_vless_url(proxy_url)
    elif proxy_url.startswith(('hysteria2://', 'hy2://')):
        protocol = 'hysteria2'
        proxy_info = parse_hysteria2_url(proxy_url)
    else: return None

    if not proxy_info: return None

    result = ProxyResult(url=proxy_url, protocol=protocol, host=proxy_info['host'], port=proxy_info['port'])
    test_sample = random.sample(test_domains, min(max_domains, len(test_domains)))
    xray_config = create_xray_config(proxy_info, protocol)

    latencies = []
    for domain in test_sample:
        success, latency = await test_proxy_through_xray(xray_path, xray_config, f"https://{domain}")
        if success:
            result.success_count += 1
            result.working_domains.append(domain)
            latencies.append(latency)
        else:
            result.fail_count += 1
    
    if latencies: result.avg_latency = sum(latencies) / len(latencies)
    return result


async def batch_check_proxies(proxy_list: List[str], test_domains: List[str], xray_path: str) -> List[ProxyResult]:
    semaphore = asyncio.Semaphore(5)
    async def sem_check(url, i):
        async with semaphore:
            print(f"[{i+1}/{len(proxy_list)}] Проверка {url[:40]}...")
            return await check_proxy(url, test_domains, xray_path)

    tasks = [sem_check(url, i) for i, url in enumerate(proxy_list)]
    results = await asyncio.gather(*tasks)
    return [r for r in results if r]


async def load_from_url(url: str) -> List[str]:
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=15) as resp:
                if resp.status == 200:
                    text = await resp.text()
                    return [l.strip() for l in text.split('\n') if l.strip() and not l.startswith('#')]
    except: pass
    return []


async def main():
    xray_path = 'xray'
    print("=" * 70)
    print("🚀 PROXY CHECKER: VLESS & HYSTERIA2")
    print("=" * 70)

    # 1. Загрузка SNI
    sni_url = 'https://raw.githubusercontent.com/Kotlas23412/proxy-checker/refs/heads/main/sni.txt'
    test_domains = await load_from_url(sni_url) or ['yandex.ru', 'google.com']

    # 2. Загрузка прокси
    proxies = []
    if os.path.exists('proxies.txt'):
        with open('proxies.txt', 'r') as f:
            lines = [l.strip() for l in f if l.strip()]
        for line in lines:
            if line.startswith('http'):
                print(f"📥 Качаю список: {line[:50]}...")
                proxies.extend(await load_from_url(line))
            else:
                proxies.append(line)
    
    proxies = list(set(proxies))
    if not proxies:
        print("❌ Нет прокси для проверки!")
        return

    print(f"✅ Найдено {len(proxies)} прокси. Начинаю...")
    results = await batch_check_proxies(proxies, test_domains, xray_path)
    
    working = [r for r in results if r.success_rate >= 50]
    
    if working:
        os.makedirs('working_proxies', exist_ok=True)
        for proto in set(r.protocol for r in working):
            proto_results = sorted([r for r in working if r.protocol == proto], key=lambda x: x.score, reverse=True)
            with open(f'working_proxies/{proto}_top.txt', 'w') as f:
                for r in proto_results: f.write(f"{r.url}\n")
        print(f"✅ Готово! Найдено рабочих: {len(working)}")
    else:
        print("⚠️ Рабочих прокси не найдено.")

if __name__ == '__main__':
    asyncio.run(main())
