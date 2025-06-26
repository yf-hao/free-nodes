#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
节点收集器和测活检测脚本
功能：
1. 从多个来源获取节点
2. 解析不同格式的订阅
3. 批量测活检测
4. 按协议分类保存
5. 生成Clash配置
"""

import asyncio
import aiohttp
import base64
import json
import yaml
import re
import os
import time
from datetime import datetime
from typing import List, Dict, Set
import logging
from urllib.parse import urlparse, parse_qs, unquote
from simple_node_checker import SimpleNodeChecker

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class NodeCollector:
    def __init__(self):
        self.session = None
        self.all_nodes = set()  # 使用集合去重
        self.working_nodes = {
            'vmess': [],
            'vless': [],
            'ss': [],
            'trojan': []
        }
        
        # 订阅源列表
        self.sub_urls = [
            "https://raw.githubusercontent.com/snakem982/proxypool/main/source/clash-meta.yaml",
            "https://raw.githubusercontent.com/snakem982/proxypool/main/source/clash-meta-2.yaml",
            "https://raw.githubusercontent.com/go4sharing/sub/main/sub.yaml",
            "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/all_configs.txt",
            "https://raw.githubusercontent.com/firefoxmmx2/v2rayshare_subcription/main/subscription/clash_sub.yaml",
            "https://raw.githubusercontent.com/Roywaller/clash_subscription/main/clash_subscription.txt",
            "https://raw.githubusercontent.com/Q3dlaXpoaQ/V2rayN_Clash_Node_Getter/main/APIs/sc0.yaml",
            "https://raw.githubusercontent.com/Q3dlaXpoaQ/V2rayN_Clash_Node_Getter/main/APIs/sc1.yaml",
            "https://raw.githubusercontent.com/Q3dlaXpoaQ/V2rayN_Clash_Node_Getter/main/APIs/sc2.yaml",
            "https://raw.githubusercontent.com/Q3dlaXpoaQ/V2rayN_Clash_Node_Getter/main/APIs/sc3.yaml",
            "https://raw.githubusercontent.com/Q3dlaXpoaQ/V2rayN_Clash_Node_Getter/main/APIs/sc4.yaml",
            "https://raw.githubusercontent.com/xiaoji235/airport-free/main/clash/naidounode.txt",
            "https://raw.githubusercontent.com/mahdibland/SSAggregator/master/sub/sub_merge_yaml.yml",
            "https://raw.githubusercontent.com/mahdibland/ShadowsocksAggregator/master/Eternity.yml",
            "https://raw.githubusercontent.com/vxiaov/free_proxies/main/clash/clash.provider.yaml",
            "https://raw.githubusercontent.com/leetomlee123/freenode/main/README.md",
            "https://raw.githubusercontent.com/chengaopan/AutoMergePublicNodes/master/list.yml",
            "https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/clash.yml",
            "https://raw.githubusercontent.com/zhangkaiitugithub/passcro/main/speednodes.yaml",
            "https://raw.githubusercontent.com/mgit0001/test_clash/main/heima.txt",
            "https://raw.githubusercontent.com/mai19950/clashgithub_com/main/site",
            "https://raw.githubusercontent.com/mai19950/sites/main/sub/v2ray/base64",
            "https://raw.githubusercontent.com/aiboboxx/v2rayfree/main/v2",
            "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub",
            "https://raw.githubusercontent.com/shahidbhutta/Clash/main/Router",
            "https://raw.githubusercontent.com/anaer/Sub/main/clash.yaml",
            "https://raw.githubusercontent.com/free18/v2ray/main/c.yaml",
            "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list.yml",
            "https://raw.githubusercontent.com/mfbpn/tg_mfbpn_sub/main/trial.yaml",
            "https://raw.githubusercontent.com/Ruk1ng001/freeSub/main/clash.yaml",
            "https://raw.githubusercontent.com/ripaojiedian/freenode/main/clash",
            "https://raw.githubusercontent.com/mfuu/v2ray/master/clash.yaml",
            "https://raw.githubusercontent.com/xiaoji235/airport-free/main/v2ray.txt",
            "https://raw.githubusercontent.com/vxiaov/free_proxies/main/links.txt",
            "https://raw.githubusercontent.com/xiaoji235/airport-free/main/v2ray/v2rayshare.txt",
            "https://raw.githubusercontent.com/MrMohebi/xray-proxy-grabber-telegram/master/collected-proxies/clash-meta/all.yaml",
            "https://raw.githubusercontent.com/ts-sf/fly/main/clash",
            "https://raw.githubusercontent.com/Barabama/FreeNodes/main/nodes/yudou66.txt",
            "https://raw.githubusercontent.com/Barabama/FreeNodes/main/nodes/clashmeta.txt",
            "https://raw.githubusercontent.com/Barabama/FreeNodes/main/nodes/ndnode.txt",
            "https://raw.githubusercontent.com/Barabama/FreeNodes/main/nodes/nodev2ray.txt",
            "https://raw.githubusercontent.com/Barabama/FreeNodes/main/nodes/nodefree.txt",
            "https://raw.githubusercontent.com/Barabama/FreeNodes/main/nodes/v2rayshare.txt",
            "https://raw.githubusercontent.com/Barabama/FreeNodes/main/nodes/wenode.txt",
            "https://raw.githubusercontent.com/ggborr/FREEE-VPN/main/4V2ray",
            "https://raw.githubusercontent.com/SamanGho/v2ray_collector/main/v2tel_links1.txt",
            "https://raw.githubusercontent.com/SamanGho/v2ray_collector/main/v2tel_links2.txt",
            "https://raw.githubusercontent.com/acymz/AutoVPN/main/data/V2.txt",
            "https://raw.githubusercontent.com/peacefish/nodefree/main/sub/proxy_cf.yaml",
            "https://raw.githubusercontent.com/darknessm427/IranConfigCollector/main/V2.txt",
            "https://raw.githubusercontent.com/NiceVPN123/NiceVPN/main/utils/pool/output.yaml",
            "https://raw.githubusercontent.com/yorkLiu/FreeV2RayNode/main/v2ray.txt",
            "https://raw.githubusercontent.com/gfpcom/free-proxy-list/main/list/ss.txt",
            "https://raw.githubusercontent.com/gfpcom/free-proxy-list/main/list/ssr.txt",
            "https://raw.githubusercontent.com/gfpcom/free-proxy-list/main/list/trojan.txt",
            "https://raw.githubusercontent.com/gfpcom/free-proxy-list/main/list/vless.txt",
            "https://raw.githubusercontent.com/gfpcom/free-proxy-list/main/list/vmess.txt",
            "https://raw.githubusercontent.com/NiceVPN123/NiceVPN/main/Clash.yaml",
            "https://raw.githubusercontent.com/lagzian/SS-Collector/main/SS/trinity_clash.yaml",
            "https://raw.githubusercontent.com/lagzian/SS-Collector/main/SS/VM_TrinityBase",
            "https://raw.githubusercontent.com/lagzian/SS-Collector/main/SS/TrinityBase",
            "https://raw.githubusercontent.com/darknessm427/IranConfigCollector/main/bulk/ss_iran.txt",
            "https://dpaste.org/Yvzvr/raw",
            "https://raw.githubusercontent.com/darknessm427/IranConfigCollector/main/bulk/trojan_iran.txt",
            "https://raw.githubusercontent.com/darknessm427/IranConfigCollector/main/bulk/vless_iran.txt",
            "https://raw.githubusercontent.com/darknessm427/IranConfigCollector/main/bulk/vmess_iran.txt",
            "https://project-d.ekt.me/sub?token=%E5%86%B2%E6%B5%AA%E5%BF%85%E5%A4%87-%E6%B5%B7%E5%A4%96"
        ]

    async def __aenter__(self):
        connector = aiohttp.TCPConnector(limit=100, limit_per_host=10)
        timeout = aiohttp.ClientTimeout(total=30)
        self.session = aiohttp.ClientSession(connector=connector, timeout=timeout)
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()

    async def fetch_url(self, url: str) -> str:
        """获取URL内容"""
        try:
            logger.info(f"正在获取: {url}")
            async with self.session.get(url) as response:
                if response.status == 200:
                    content = await response.text()
                    logger.info(f"✅ 成功获取 {url} ({len(content)} 字符)")
                    return content
                else:
                    logger.warning(f"❌ 获取失败 {url} - HTTP {response.status}")
                    return ""
        except Exception as e:
            logger.error(f"❌ 获取失败 {url} - {e}")
            return ""

    def parse_base64_subscription(self, content: str) -> List[str]:
        """解析base64编码的订阅"""
        nodes = []
        try:
            # 尝试解码base64
            decoded = base64.b64decode(content + '=' * (4 - len(content) % 4)).decode('utf-8')
            lines = decoded.strip().split('\n')
            for line in lines:
                line = line.strip()
                if line and (line.startswith('vmess://') or line.startswith('vless://') or 
                           line.startswith('ss://') or line.startswith('trojan://')):
                    nodes.append(line)
        except Exception as e:
            logger.debug(f"Base64解码失败: {e}")
        return nodes

    def parse_yaml_subscription(self, content: str) -> List[str]:
        """解析YAML格式的订阅"""
        nodes = []
        try:
            data = yaml.safe_load(content)
            if isinstance(data, dict):
                # Clash格式
                proxies = data.get('proxies', [])
                for proxy in proxies:
                    if isinstance(proxy, dict):
                        node_url = self.clash_proxy_to_url(proxy)
                        if node_url:
                            nodes.append(node_url)
        except Exception as e:
            logger.debug(f"YAML解析失败: {e}")
        return nodes

    def clash_proxy_to_url(self, proxy: Dict) -> str:
        """将Clash代理配置转换为URL"""
        try:
            proxy_type = proxy.get('type', '').lower()
            server = proxy.get('server', '')
            port = proxy.get('port', '')
            name = proxy.get('name', '')
            
            if proxy_type == 'vmess':
                config = {
                    'v': '2',
                    'ps': name,
                    'add': server,
                    'port': str(port),
                    'id': proxy.get('uuid', ''),
                    'aid': str(proxy.get('alterId', 0)),
                    'scy': proxy.get('cipher', 'auto'),
                    'net': proxy.get('network', 'tcp'),
                    'type': proxy.get('ws-opts', {}).get('headers', {}).get('Host', 'none'),
                    'host': proxy.get('ws-opts', {}).get('headers', {}).get('Host', ''),
                    'path': proxy.get('ws-opts', {}).get('path', ''),
                    'tls': 'tls' if proxy.get('tls', False) else ''
                }
                encoded = base64.b64encode(json.dumps(config).encode()).decode()
                return f"vmess://{encoded}"
                
            elif proxy_type == 'vless':
                params = []
                if proxy.get('flow'):
                    params.append(f"flow={proxy['flow']}")
                if proxy.get('security'):
                    params.append(f"security={proxy['security']}")
                if proxy.get('network'):
                    params.append(f"type={proxy['network']}")
                
                param_str = '&'.join(params)
                return f"vless://{proxy.get('uuid', '')}@{server}:{port}?{param_str}#{name}"
                
            elif proxy_type == 'ss':
                method = proxy.get('cipher', '')
                password = proxy.get('password', '')
                auth = base64.b64encode(f"{method}:{password}".encode()).decode()
                return f"ss://{auth}@{server}:{port}#{name}"
                
            elif proxy_type == 'trojan':
                password = proxy.get('password', '')
                return f"trojan://{password}@{server}:{port}#{name}"
                
        except Exception as e:
            logger.debug(f"Clash代理转换失败: {e}")
        return ""

    def parse_plain_text(self, content: str) -> List[str]:
        """解析纯文本格式的节点"""
        nodes = []
        lines = content.strip().split('\n')
        for line in lines:
            line = line.strip()
            if line and (line.startswith('vmess://') or line.startswith('vless://') or 
                       line.startswith('ss://') or line.startswith('trojan://')):
                nodes.append(line)
        return nodes

    def extract_nodes_from_markdown(self, content: str) -> List[str]:
        """从Markdown文件中提取节点"""
        nodes = []
        # 查找代码块中的节点
        code_blocks = re.findall(r'```[\s\S]*?```', content)
        for block in code_blocks:
            lines = block.strip('`').split('\n')
            for line in lines:
                line = line.strip()
                if line and (line.startswith('vmess://') or line.startswith('vless://') or 
                           line.startswith('ss://') or line.startswith('trojan://')):
                    nodes.append(line)
        
        # 查找直接的节点链接
        direct_nodes = re.findall(r'(vmess://[^\s]+|vless://[^\s]+|ss://[^\s]+|trojan://[^\s]+)', content)
        nodes.extend(direct_nodes)
        
        return nodes

    async def collect_all_nodes(self) -> Set[str]:
        """收集所有节点"""
        logger.info(f"开始从 {len(self.sub_urls)} 个来源收集节点...")
        
        # 并发获取所有订阅
        tasks = [self.fetch_url(url) for url in self.sub_urls]
        contents = await asyncio.gather(*tasks, return_exceptions=True)
        
        all_nodes = set()
        
        for i, content in enumerate(contents):
            if isinstance(content, Exception):
                continue
                
            if not content:
                continue
                
            url = self.sub_urls[i]
            nodes = []
            
            # 根据内容类型解析节点
            if url.endswith('.yaml') or url.endswith('.yml'):
                nodes = self.parse_yaml_subscription(content)
            elif url.endswith('.md'):
                nodes = self.extract_nodes_from_markdown(content)
            else:
                # 尝试不同的解析方式
                nodes = self.parse_plain_text(content)
                if not nodes:
                    nodes = self.parse_base64_subscription(content)
                if not nodes:
                    nodes = self.parse_yaml_subscription(content)
            
            if nodes:
                logger.info(f"📦 从 {url} 解析到 {len(nodes)} 个节点")
                all_nodes.update(nodes)
            else:
                logger.warning(f"⚠️ 从 {url} 未解析到任何节点")
        
        logger.info(f"🎯 总共收集到 {len(all_nodes)} 个唯一节点")
        return all_nodes

    def classify_nodes(self, working_results: List[Dict]) -> Dict[str, List[str]]:
        """按协议分类节点"""
        classified = {
            'vmess': [],
            'vless': [],
            'ss': [],
            'trojan': []
        }
        
        for result in working_results:
            if result['success']:
                protocol = result['protocol']
                if protocol in classified:
                    classified[protocol].append(result['url'])
        
        return classified

    def generate_clash_config(self, working_results: List[Dict]) -> Dict:
        """生成Clash配置"""
        proxies = []
        proxy_names = []
        
        for result in working_results:
            if not result['success']:
                continue
                
            try:
                checker = SimpleNodeChecker()
                node = checker.parse_node(result['url'])
                if not node:
                    continue
                
                proxy_name = f"{node['remarks'] or node['address']}_{node['port']}"
                proxy_names.append(proxy_name)
                
                if node['protocol'] == 'vmess':
                    proxy = {
                        'name': proxy_name,
                        'type': 'vmess',
                        'server': node['address'],
                        'port': node['port'],
                        'uuid': node['id'],
                        'alterId': node.get('alterId', 0),
                        'cipher': node.get('security', 'auto'),
                        'network': node.get('network', 'tcp'),
                        'tls': node.get('tls') == 'tls'
                    }
                    
                elif node['protocol'] == 'vless':
                    proxy = {
                        'name': proxy_name,
                        'type': 'vless',
                        'server': node['address'],
                        'port': node['port'],
                        'uuid': node['id'],
                        'tls': node.get('tls') == 'tls'
                    }
                    
                elif node['protocol'] == 'ss':
                    proxy = {
                        'name': proxy_name,
                        'type': 'ss',
                        'server': node['address'],
                        'port': node['port'],
                        'cipher': node.get('method', 'aes-256-gcm'),
                        'password': node.get('password', '')
                    }
                    
                elif node['protocol'] == 'trojan':
                    proxy = {
                        'name': proxy_name,
                        'type': 'trojan',
                        'server': node['address'],
                        'port': node['port'],
                        'password': node.get('password', ''),
                        'sni': node.get('sni', ''),
                        'skip-cert-verify': True
                    }
                
                if proxy:
                    proxies.append(proxy)
                    
            except Exception as e:
                logger.debug(f"生成Clash配置失败: {e}")
                continue
        
        # 生成完整的Clash配置
        clash_config = {
            'port': 7890,
            'socks-port': 7891,
            'allow-lan': True,
            'mode': 'Rule',
            'log-level': 'info',
            'external-controller': '127.0.0.1:9090',
            'proxies': proxies,
            'proxy-groups': [
                {
                    'name': 'PROXY',
                    'type': 'select',
                    'proxies': ['♻️ 自动选择'] + proxy_names
                },
                {
                    'name': '♻️ 自动选择',
                    'type': 'url-test',
                    'proxies': proxy_names,
                    'url': 'http://www.gstatic.com/generate_204',
                    'interval': 300
                }
            ],
            'rules': [
                'DOMAIN-SUFFIX,google.com,PROXY',
                'DOMAIN-SUFFIX,youtube.com,PROXY',
                'DOMAIN-SUFFIX,facebook.com,PROXY',
                'DOMAIN-SUFFIX,twitter.com,PROXY',
                'DOMAIN-SUFFIX,telegram.org,PROXY',
                'GEOIP,CN,DIRECT',
                'MATCH,PROXY'
            ]
        }
        
        return clash_config

    def create_directories(self):
        """创建必要的目录"""
        os.makedirs('nodes', exist_ok=True)

    def save_results(self, classified_nodes: Dict[str, List[str]], clash_config: Dict):
        """保存结果到文件"""
        self.create_directories()
        
        # 保存各协议节点
        for protocol, nodes in classified_nodes.items():
            if nodes:
                filename = f'nodes/{protocol}.txt' if protocol != 'ss' else 'nodes/shadowsocks.txt'
                with open(filename, 'w', encoding='utf-8') as f:
                    for node in nodes:
                        f.write(node + '\n')
                logger.info(f"💾 保存 {len(nodes)} 个 {protocol.upper()} 节点到 {filename}")
        
        # 保存V2Ray格式（包含vmess和vless）
        v2ray_nodes = classified_nodes['vmess'] + classified_nodes['vless']
        if v2ray_nodes:
            with open('nodes/v2ray.txt', 'w', encoding='utf-8') as f:
                for node in v2ray_nodes:
                    f.write(node + '\n')
            logger.info(f"💾 保存 {len(v2ray_nodes)} 个 V2Ray 节点到 nodes/v2ray.txt")
        
        # 保存Clash配置
        if clash_config['proxies']:
            with open('nodes/clash.yaml', 'w', encoding='utf-8') as f:
                yaml.dump(clash_config, f, default_flow_style=False, allow_unicode=True)
            logger.info(f"💾 保存 {len(clash_config['proxies'])} 个节点的 Clash 配置到 nodes/clash.yaml")

    async def run(self):
        """运行完整的收集和测活流程"""
        start_time = time.time()
        
        # 1. 收集所有节点
        logger.info("🚀 开始节点收集和测活流程...")
        all_nodes = await self.collect_all_nodes()
        
        if not all_nodes:
            logger.error("❌ 未收集到任何节点")
            return
        
        # 2. 测活检测
        logger.info(f"🔍 开始测活检测 {len(all_nodes)} 个节点...")
        checker = SimpleNodeChecker(timeout=5, max_workers=50)
        results = checker.check_nodes_batch(list(all_nodes))
        
        # 3. 过滤可用节点
        working_results = [r for r in results if r['success']]
        logger.info(f"✅ 找到 {len(working_results)} 个可用节点")
        
        if not working_results:
            logger.error("❌ 没有可用的节点")
            return
        
        # 4. 按协议分类
        classified_nodes = self.classify_nodes(working_results)
        
        # 5. 生成Clash配置
        clash_config = self.generate_clash_config(working_results)
        
        # 6. 保存结果
        self.save_results(classified_nodes, clash_config)
        
        # 7. 生成统计报告
        total_time = time.time() - start_time
        logger.info(f"🎉 任务完成！总用时: {total_time:.1f}秒")
        logger.info("📊 统计结果:")
        logger.info(f"  - 总收集节点: {len(all_nodes)}")
        logger.info(f"  - 可用节点: {len(working_results)}")
        logger.info(f"  - 成功率: {len(working_results)/len(all_nodes)*100:.1f}%")
        logger.info(f"  - VMess节点: {len(classified_nodes['vmess'])}")
        logger.info(f"  - VLESS节点: {len(classified_nodes['vless'])}")
        logger.info(f"  - Shadowsocks节点: {len(classified_nodes['ss'])}")
        logger.info(f"  - Trojan节点: {len(classified_nodes['trojan'])}")


async def main():
    """主函数"""
    async with NodeCollector() as collector:
        await collector.run()


if __name__ == "__main__":
    asyncio.run(main())
