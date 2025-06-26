#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import base64
import yaml
import json
import re
from datetime import datetime
import os

class NodeCollector:
    def __init__(self):
        self.v2ray_nodes = []
        self.ss_nodes = []
        self.trojan_nodes = []
        
    def fetch_from_sources(self):
        """从各种来源获取节点"""
        sources = [
            "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list.txt",
            "https://raw.githubusercontent.com/freefq/free/master/v2",
            "https://raw.githubusercontent.com/aiboboxx/v2rayfree/main/v2",
            "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub",
            "https://raw.githubusercontent.com/mfuu/v2ray/master/v2ray",
            "https://raw.githubusercontent.com/tbbatbb/Proxy/master/dist/v2ray.config.txt",
        ]
        
        for source in sources:
            try:
                print(f"🔍 获取节点: {source}")
                response = requests.get(source, timeout=15, headers={
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                })
                if response.status_code == 200:
                    self.parse_nodes(response.text)
            except Exception as e:
                print(f"❌ 获取失败 {source}: {e}")
    
    def parse_nodes(self, content):
        """解析节点内容"""
        try:
            # 尝试 base64 解码
            if self.is_base64(content.strip()):
                content = base64.b64decode(content.strip()).decode('utf-8')
            
            lines = content.strip().split('\n')
            for line in lines:
                line = line.strip()
                if line.startswith('vmess://'):
                    self.v2ray_nodes.append(line)
                elif line.startswith('vless://'):
                    self.v2ray_nodes.append(line)
                elif line.startswith('ss://'):
                    self.ss_nodes.append(line)
                elif line.startswith('trojan://'):
                    self.trojan_nodes.append(line)
                    
        except Exception as e:
            print(f"❌ 解析失败: {e}")
    
    def is_base64(self, s):
        """检查是否为 base64 编码"""
        try:
            if len(s) % 4 != 0:
                return False
            decoded = base64.b64decode(s, validate=True)
            return base64.b64encode(decoded).decode() == s
        except:
            return False
    
    def generate_clash_config(self):
        """生成 Clash 配置"""
        config = {
            'port': 7890,
            'socks-port': 7891,
            'allow-lan': True,
            'mode': 'rule',
            'log-level': 'info',
            'external-controller': '127.0.0.1:9090',
            'proxies': [],
            'proxy-groups': [
                {
                    'name': '🚀 节点选择',
                    'type': 'select',
                    'proxies': ['♻️ 自动选择', '🎯 全球直连']
                },
                {
                    'name': '♻️ 自动选择',
                    'type': 'url-test',
                    'proxies': [],
                    'url': 'http://www.gstatic.com/generate_204',
                    'interval': 300
                },
                {
                    'name': '🎯 全球直连',
                    'type': 'select',
                    'proxies': ['DIRECT']
                }
            ],
            'rules': [
                'DOMAIN-SUFFIX,local,🎯 全球直连',
                'IP-CIDR,127.0.0.0/8,🎯 全球直连',
                'IP-CIDR,172.16.0.0/12,🎯 全球直连',
                'IP-CIDR,192.168.0.0/16,🎯 全球直连',
                'IP-CIDR,10.0.0.0/8,🎯 全球直连',
                'GEOIP,CN,🎯 全球直连',
                'MATCH,🚀 节点选择'
            ]
        }
        
        return yaml.dump(config, default_flow_style=False, allow_unicode=True)
    
    def save_nodes(self):
        """保存节点到文件"""
        os.makedirs('nodes', exist_ok=True)
        os.makedirs('api', exist_ok=True)
        
        # 去重并限制数量
        self.v2ray_nodes = list(dict.fromkeys(self.v2ray_nodes))[:100]
        self.ss_nodes = list(dict.fromkeys(self.ss_nodes))[:50] 
        self.trojan_nodes = list(dict.fromkeys(self.trojan_nodes))[:30]
        
        # 保存 V2Ray 节点
        if self.v2ray_nodes:
            content = '\n'.join(self.v2ray_nodes)
            with open('nodes/v2ray.txt', 'w', encoding='utf-8') as f:
                f.write(base64.b64encode(content.encode()).decode())
        
        # 保存 SS 节点
        if self.ss_nodes:
            content = '\n'.join(self.ss_nodes)
            with open('nodes/shadowsocks.txt', 'w', encoding='utf-8') as f:
                f.write(base64.b64encode(content.encode()).decode())
        
        # 保存 Trojan 节点
        if self.trojan_nodes:
            content = '\n'.join(self.trojan_nodes)
            with open('nodes/trojan.txt', 'w', encoding='utf-8') as f:
                f.write(base64.b64encode(content.encode()).decode())
        
        # 生成 Clash 配置
        with open('nodes/clash.yaml', 'w', encoding='utf-8') as f:
            f.write(self.generate_clash_config())
        
        # 生成 API 数据
        api_data = {
            'updated_at': datetime.utcnow().isoformat() + 'Z',
            'total_nodes': len(self.v2ray_nodes) + len(self.ss_nodes) + len(self.trojan_nodes),
            'v2ray_count': len(self.v2ray_nodes),
            'ss_count': len(self.ss_nodes),
            'trojan_count': len(self.trojan_nodes),
            'last_update': datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')
        }
        
        with open('api/nodes.json', 'w', encoding='utf-8') as f:
            json.dump(api_data, f, indent=2, ensure_ascii=False)
        
        print(f"✅ 节点保存完成:")
        print(f"   V2Ray: {len(self.v2ray_nodes)} 个")
        print(f"   SS: {len(self.ss_nodes)} 个") 
        print(f"   Trojan: {len(self.trojan_nodes)} 个")

if __name__ == "__main__":
    collector = NodeCollector()
    collector.fetch_from_sources()
    collector.save_nodes()
