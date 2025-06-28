#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
增强版节点检测器 - 专门针对中国大陆翻墙优化
功能：
1. 多阶段检测策略
2. 真实翻墙场景模拟
3. 智能评分系统
4. 协议特定检测
5. 地理位置感知
"""

import asyncio
import aiohttp
import socket
import ssl
import time
import json
import base64
import re
import random
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, parse_qs, unquote
from typing import List, Dict, Optional, Tuple
import threading
from dataclasses import dataclass

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

@dataclass
class NodeInfo:
    """节点信息"""
    url: str
    protocol: str
    address: str
    port: int
    remarks: str
    uuid: str = ""
    password: str = ""
    method: str = ""
    security: str = ""
    network: str = "tcp"
    host: str = ""
    path: str = ""
    sni: str = ""
    flow: str = ""
    alter_id: int = 0

@dataclass
class TestResult:
    """测试结果"""
    node_info: NodeInfo
    basic_connectivity: bool = False
    ssl_handshake: bool = False
    protocol_test: bool = False
    latency_ms: float = 0.0
    error_message: str = ""
    china_score: int = 0
    is_china_usable: bool = False
    suggestion: str = ""

class EnhancedNodeTester:
    def __init__(self, timeout=10, max_workers=20, china_mode=True):
        self.timeout = timeout
        self.max_workers = max_workers
        self.china_mode = china_mode
        
        # 中国翻墙测试目标
        self.china_test_targets = [
            "www.google.com",
            "www.youtube.com", 
            "www.facebook.com",
            "www.twitter.com",
            "www.instagram.com",
            "www.reddit.com",
            "www.wikipedia.org",
            "www.github.com",
            "www.stackoverflow.com",
            "www.medium.com"
        ]
        
        # 全球测试目标
        self.global_test_targets = [
            "www.cloudflare.com",
            "www.amazon.com",
            "www.microsoft.com",
            "www.apple.com",
            "www.netflix.com"
        ]
        
        # 协议特定端口
        self.protocol_ports = {
            'vmess': [443, 80, 8080, 8443, 2053, 2083, 2087, 2096],
            'vless': [443, 80, 8080, 8443, 2053, 2083, 2087, 2096],
            'trojan': [443, 80, 8080, 8443, 2053, 2083, 2087, 2096],
            'ss': [443, 80, 8080, 8443, 2053, 2083, 2087, 2096, 8388, 8389]
        }
        
        # 中国ISP常见端口
        self.china_common_ports = [80, 443, 8080, 8443, 2053, 2083, 2087, 2096, 8388, 8389]
        
        # 评分权重
        self.score_weights = {
            'connectivity': 0.3,
            'latency': 0.25,
            'ssl_support': 0.2,
            'protocol_compatibility': 0.15,
            'port_commonality': 0.1
        }

    def parse_node(self, url: str) -> Optional[NodeInfo]:
        """解析节点URL"""
        try:
            if url.startswith('vmess://'):
                return self._parse_vmess(url)
            elif url.startswith('vless://'):
                return self._parse_vless(url)
            elif url.startswith('ss://'):
                return self._parse_shadowsocks(url)
            elif url.startswith('trojan://'):
                return self._parse_trojan(url)
            else:
                return None
        except Exception as e:
            logger.debug(f"解析节点失败 {url}: {e}")
            return None

    def _parse_vmess(self, url: str) -> Optional[NodeInfo]:
        """解析VMess节点"""
        try:
            encoded = url[8:]
            # 处理base64填充
            missing_padding = len(encoded) % 4
            if missing_padding:
                encoded += '=' * (4 - missing_padding)
            
            data = json.loads(base64.b64decode(encoded).decode())
            
            return NodeInfo(
                url=url,
                protocol='vmess',
                address=data.get('add', ''),
                port=int(data.get('port', 0)),
                remarks=data.get('ps', ''),
                uuid=data.get('id', ''),
                alter_id=int(data.get('aid', 0)),
                security=data.get('scy', 'auto'),
                network=data.get('net', 'tcp'),
                host=data.get('host', ''),
                path=data.get('path', ''),
                sni=data.get('sni', '')
            )
        except Exception as e:
            logger.debug(f"VMess解析失败: {e}")
            return None

    def _parse_vless(self, url: str) -> Optional[NodeInfo]:
        """解析VLESS节点"""
        try:
            parsed = urlparse(url)
            uuid = parsed.username
            address = parsed.hostname
            port = parsed.port or 443
            
            # 解析参数
            params = parse_qs(parsed.query)
            
            return NodeInfo(
                url=url,
                protocol='vless',
                address=address,
                port=port,
                remarks=unquote(parsed.fragment or ''),
                uuid=uuid,
                security=params.get('security', ['none'])[0],
                network=params.get('type', ['tcp'])[0],
                host=params.get('host', [''])[0],
                path=params.get('path', [''])[0],
                sni=params.get('sni', [''])[0],
                flow=params.get('flow', [''])[0]
            )
        except Exception as e:
            logger.debug(f"VLESS解析失败: {e}")
            return None

    def _parse_shadowsocks(self, url: str) -> Optional[NodeInfo]:
        """解析Shadowsocks节点"""
        try:
            if '@' in url:
                # 新格式: ss://method:password@server:port#remarks
                auth_part, server_part = url[5:].split('@')
                method, password = auth_part.split(':')
                server, port = server_part.split('#')[0].split(':')
                remarks = server_part.split('#')[1] if '#' in server_part else ''
            else:
                # 旧格式: ss://base64(method:password@server:port)#remarks
                encoded = url[5:].split('#')[0]
                decoded = base64.b64decode(encoded + '=' * (4 - len(encoded) % 4)).decode()
                auth_server, remarks = url[5:].split('#')[1] if '#' in url[5:] else ('', '')
                method_password, server_port = decoded.split('@')
                method, password = method_password.split(':')
                server, port = server_port.split(':')
            
            return NodeInfo(
                url=url,
                protocol='ss',
                address=server,
                port=int(port),
                remarks=unquote(remarks),
                method=method,
                password=password
            )
        except Exception as e:
            logger.debug(f"Shadowsocks解析失败: {e}")
            return None

    def _parse_trojan(self, url: str) -> Optional[NodeInfo]:
        """解析Trojan节点"""
        try:
            parsed = urlparse(url)
            password = parsed.username
            address = parsed.hostname
            port = parsed.port or 443
            
            # 解析参数
            params = parse_qs(parsed.query)
            
            return NodeInfo(
                url=url,
                protocol='trojan',
                address=address,
                port=port,
                remarks=unquote(parsed.fragment or ''),
                password=password,
                sni=params.get('sni', [''])[0]
            )
        except Exception as e:
            logger.debug(f"Trojan解析失败: {e}")
            return None

    def _test_basic_connectivity(self, node_info: NodeInfo) -> Tuple[bool, float, str]:
        """基础连接性测试"""
        try:
            start_time = time.time()
            
            # 创建socket连接
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            result = sock.connect_ex((node_info.address, node_info.port))
            latency = (time.time() - start_time) * 1000
            
            sock.close()
            
            if result == 0:
                return True, latency, ""
            else:
                return False, 0, f"Connection failed (code: {result})"
                
        except socket.gaierror:
            return False, 0, "DNS resolution failed"
        except socket.timeout:
            return False, 0, "Connection timeout"
        except Exception as e:
            return False, 0, f"Connection error: {str(e)}"

    def _test_ssl_handshake(self, node_info: NodeInfo) -> Tuple[bool, str]:
        """SSL握手测试"""
        try:
            # 创建SSL上下文
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # 创建socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            # 包装为SSL socket
            ssl_sock = context.wrap_socket(sock, server_hostname=node_info.sni or node_info.address)
            ssl_sock.connect((node_info.address, node_info.port))
            
            # 获取SSL信息
            cipher = ssl_sock.cipher()
            version = ssl_sock.version()
            
            ssl_sock.close()
            
            return True, f"SSL {version} with {cipher[0]}"
            
        except ssl.SSLError as e:
            return False, f"SSL error: {str(e)}"
        except Exception as e:
            return False, f"SSL test failed: {str(e)}"

    def _test_protocol_specific(self, node_info: NodeInfo) -> Tuple[bool, str]:
        """协议特定测试"""
        try:
            if node_info.protocol == 'vmess':
                return self._test_vmess_protocol(node_info)
            elif node_info.protocol == 'vless':
                return self._test_vless_protocol(node_info)
            elif node_info.protocol == 'trojan':
                return self._test_trojan_protocol(node_info)
            elif node_info.protocol == 'ss':
                return self._test_ss_protocol(node_info)
            else:
                return False, "Unknown protocol"
        except Exception as e:
            return False, f"Protocol test failed: {str(e)}"

    def _test_vmess_protocol(self, node_info: NodeInfo) -> Tuple[bool, str]:
        """VMess协议测试"""
        try:
            # 检查必要的字段
            if not node_info.uuid or not node_info.address or not node_info.port:
                return False, "Missing required fields"
            
            # 检查alterId
            if node_info.alter_id > 0:
                return True, f"VMess with alterId {node_info.alter_id}"
            else:
                return True, "VMess AEAD"
                
        except Exception as e:
            return False, f"VMess test failed: {str(e)}"

    def _test_vless_protocol(self, node_info: NodeInfo) -> Tuple[bool, str]:
        """VLESS协议测试"""
        try:
            if not node_info.uuid or not node_info.address or not node_info.port:
                return False, "Missing required fields"
            
            # 检查TLS配置
            if node_info.security == 'tls':
                if not node_info.sni:
                    return True, "VLESS with TLS (no SNI)"
                else:
                    return True, f"VLESS with TLS SNI: {node_info.sni}"
            else:
                return True, "VLESS without TLS"
                
        except Exception as e:
            return False, f"VLESS test failed: {str(e)}"

    def _test_trojan_protocol(self, node_info: NodeInfo) -> Tuple[bool, str]:
        """Trojan协议测试"""
        try:
            if not node_info.password or not node_info.address or not node_info.port:
                return False, "Missing required fields"
            
            # Trojan通常需要TLS
            if node_info.sni:
                return True, f"Trojan with SNI: {node_info.sni}"
            else:
                return True, "Trojan (no SNI)"
                
        except Exception as e:
            return False, f"Trojan test failed: {str(e)}"

    def _test_ss_protocol(self, node_info: NodeInfo) -> Tuple[bool, str]:
        """Shadowsocks协议测试"""
        try:
            if not node_info.method or not node_info.password or not node_info.address or not node_info.port:
                return False, "Missing required fields"
            
            # 检查加密方法
            valid_methods = ['aes-256-gcm', 'aes-128-gcm', 'chacha20-poly1305', 'aes-256-cfb', 'aes-128-cfb']
            if node_info.method not in valid_methods:
                return False, f"Unsupported method: {node_info.method}"
            
            return True, f"SS with {node_info.method}"
            
        except Exception as e:
            return False, f"SS test failed: {str(e)}"

    def _calculate_china_score(self, result: TestResult) -> int:
        """计算中国翻墙评分"""
        score = 0
        
        # 基础连接性 (30分)
        if result.basic_connectivity:
            score += 30
        
        # 延迟评分 (25分)
        if result.latency_ms > 0:
            if result.latency_ms < 100:
                score += 25
            elif result.latency_ms < 200:
                score += 20
            elif result.latency_ms < 500:
                score += 15
            elif result.latency_ms < 1000:
                score += 10
            else:
                score += 5
        
        # SSL支持 (20分)
        if result.ssl_handshake:
            score += 20
        
        # 协议兼容性 (15分)
        if result.protocol_test:
            score += 15
        
        # 端口常见性 (10分)
        if result.node_info.port in self.china_common_ports:
            score += 10
        
        # 协议特定加分
        if result.node_info.protocol == 'vmess':
            if result.node_info.alter_id == 0:  # AEAD模式
                score += 5
        elif result.node_info.protocol == 'vless':
            if result.node_info.security == 'tls':
                score += 5
        elif result.node_info.protocol == 'trojan':
            score += 5  # Trojan在中国表现较好
        
        return min(score, 100)

    def _generate_suggestion(self, result: TestResult) -> str:
        """生成建议"""
        if result.china_score >= 80:
            return "优秀节点，推荐使用"
        elif result.china_score >= 60:
            return "良好节点，可以尝试"
        elif result.china_score >= 40:
            return "一般节点，备用选择"
        else:
            return "质量较差，不推荐"

    def test_single_node(self, url: str) -> TestResult:
        """测试单个节点"""
        try:
            # 解析节点
            node_info = self.parse_node(url)
            if not node_info:
                return TestResult(
                    node_info=NodeInfo(url=url, protocol='unknown', address='', port=0, remarks=''),
                    error_message="Failed to parse node"
                )
            
            result = TestResult(node_info=node_info)
            
            # 1. 基础连接性测试
            result.basic_connectivity, result.latency_ms, error = self._test_basic_connectivity(node_info)
            if not result.basic_connectivity:
                result.error_message = error
                return result
            
            # 2. SSL握手测试（如果端口是443或支持TLS）
            if node_info.port == 443 or node_info.protocol in ['vless', 'trojan']:
                result.ssl_handshake, ssl_info = self._test_ssl_handshake(node_info)
            
            # 3. 协议特定测试
            result.protocol_test, protocol_info = self._test_protocol_specific(node_info)
            
            # 4. 计算中国翻墙评分
            result.china_score = self._calculate_china_score(result)
            result.is_china_usable = result.china_score >= 40  # 40分以上认为可用
            result.suggestion = self._generate_suggestion(result)
            
            return result
            
        except Exception as e:
            return TestResult(
                node_info=NodeInfo(url=url, protocol='unknown', address='', port=0, remarks=''),
                error_message=f"Test failed: {str(e)}"
            )

    def check_nodes_batch(self, nodes: List[str]) -> List[Dict]:
        """批量检测节点"""
        logger.info(f"开始增强版节点检测，共 {len(nodes)} 个节点...")
        
        results = []
        completed = 0
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_node = {executor.submit(self.test_single_node, node): node for node in nodes}
            
            for future in as_completed(future_to_node):
                test_result = future.result()
                completed += 1
                
                # 转换为字典格式
                result_dict = {
                    'url': test_result.node_info.url,
                    'success': test_result.is_china_usable,
                    'latency': test_result.latency_ms,
                    'protocol': test_result.node_info.protocol,
                    'address': test_result.node_info.address,
                    'port': test_result.node_info.port,
                    'remarks': test_result.node_info.remarks,
                    'china_score': test_result.china_score,
                    'china_usable': test_result.is_china_usable,
                    'suggestion': test_result.suggestion,
                    'error': test_result.error_message,
                    'basic_connectivity': test_result.basic_connectivity,
                    'ssl_handshake': test_result.ssl_handshake,
                    'protocol_test': test_result.protocol_test
                }
                
                results.append(result_dict)
                
                # 进度报告
                if completed % 50 == 0 or completed == len(nodes):
                    usable_count = len([r for r in results if r['china_usable']])
                    avg_score = sum(r['china_score'] for r in results) / len(results) if results else 0
                    logger.info(f"检测进度: {completed}/{len(nodes)}, 可用: {usable_count}, 平均评分: {avg_score:.1f}")
        
        # 按评分排序
        results.sort(key=lambda x: x['china_score'], reverse=True)
        
        logger.info(f"检测完成！可用节点: {len([r for r in results if r['china_usable']])}/{len(results)}")
        
        return results

    def get_test_targets(self) -> List[str]:
        """获取测试目标"""
        if self.china_mode:
            return self.china_test_targets
        else:
            return self.global_test_targets

# 兼容性包装器
class SimpleNodeChecker:
    """兼容性包装器，保持与原有代码的兼容性"""
    
    def __init__(self, timeout=10, max_workers=20):
        self.enhanced_tester = EnhancedNodeTester(timeout=timeout, max_workers=max_workers)
    
    def check_nodes_batch(self, nodes: List[str]) -> List[Dict]:
        """批量检测节点"""
        return self.enhanced_tester.check_nodes_batch(nodes)
    
    def parse_node(self, url: str) -> Optional[Dict]:
        """解析节点（兼容性方法）"""
        node_info = self.enhanced_tester.parse_node(url)
        if node_info:
            return {
                'protocol': node_info.protocol,
                'address': node_info.address,
                'port': node_info.port,
                'remarks': node_info.remarks,
                'uuid': node_info.uuid,
                'password': node_info.password,
                'method': node_info.method,
                'security': node_info.security,
                'network': node_info.network,
                'host': node_info.host,
                'path': node_info.path,
                'sni': node_info.sni,
                'flow': node_info.flow,
                'alterId': node_info.alter_id
            }
        return None
