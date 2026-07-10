"""
HypoMux sing-box 配置生成器 - 第三阶段下半场 · 任务2

把【路由规则页】TableWidget 中的进程级分流规则，动态序列化为标准的
sing-box 兼容 config.json。

架构映射：
- inbounds : 单一 tun 入站（interface_name=HypoMux-Tun，auto_route + strict_route），
  全局吸入系统 TCP/UDP 流量。
- outbounds: 三个 socks 出站，分别对接 Python 本地多端口出站池：
    nic_ethernet -> 127.0.0.1:2001  （有线/PPP 强制单网卡）
    nic_wifi     -> 127.0.0.1:2002  （无线 Wi-Fi 强制单网卡）
    aggregation  -> 127.0.0.1:2003  （多网卡 Round-Robin 聚合叠加）
  另含 direct（保底直连）。
- route.rules: 顶部按固定顺序强插后端自流量防环、DNS 劫持、ICMP 网络
  直连防御矩阵，再按用户表格逐条生成 {process_name:[...], outbound:...}；
  未命中规则的默认兜底 final 一律指向 aggregation，实现 TCP/UDP 全局聚合叠加。

纯逻辑模块，零 Qt 依赖，防御式编程，绝不抛出未捕获异常。
"""

from __future__ import annotations

import json
import ipaddress
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# 三大出站标签（与 UI / 多端口出站池端口一一对应）
OUTBOUND_ETHERNET = "nic_ethernet"
OUTBOUND_WIFI = "nic_wifi"
OUTBOUND_AGGREGATION = "aggregation"
OUTBOUND_DIRECT = "direct"
OUTBOUND_UDP_PRIMARY = "udp-primary"

# 合法出站标签集合（用于校验用户表格输入）
VALID_OUTBOUNDS = {
    OUTBOUND_ETHERNET,
    OUTBOUND_WIFI,
    OUTBOUND_AGGREGATION,
    OUTBOUND_DIRECT,
}

# Python 本地多端口出站池端口（任务1）
PORT_ETHERNET = 2001
PORT_WIFI = 2002
PORT_AGGREGATION = 2003

TUN_INTERFACE_NAME = "HypoMux-Tun"
TUN_GATEWAY = "172.19.0.1"
TUN_ADDRESS = f"{TUN_GATEWAY}/30"
DNS_LOCAL_TAG = "dns-local"
DNS_FAKEIP_TAG = "dns-fakeip"
SINGBOX_EXE = "sing-box.exe"


def _socks_outbound(tag: str, port: int) -> Dict[str, Any]:
    """构造一个指向本地 Python 出站池端口的 socks 出站块。"""
    return {
        "type": "socks",
        "tag": tag,
        "server": "127.0.0.1",
        "server_port": port,
        "version": "5",
    }


def _is_valid_outbound_tag(tag: str) -> bool:
    """校验出站标签；允许固定标签与 nic_真实网卡别名动态标签。"""
    if tag in VALID_OUTBOUNDS:
        return True
    return tag.startswith("nic_") and len(tag) > 4


def _dynamic_nic_port(tag: str) -> int:
    """把动态网卡别名标签映射到当前三通道出站池端口。"""
    alias = tag[4:].lower()
    if any(key in alias for key in ("wlan", "wi-fi", "wifi", "wireless", "无线")):
        return PORT_WIFI
    return PORT_ETHERNET


def build_config(
    rules: Optional[List[Dict[str, Any]]] = None,
    *,
    ethernet_port: int = PORT_ETHERNET,
    wifi_port: int = PORT_WIFI,
    aggregation_port: int = PORT_AGGREGATION,
    tun_name: str = TUN_INTERFACE_NAME,
    default_outbound: str = OUTBOUND_AGGREGATION,
    dns_bind_ip: str = "",
    dns_bind_interface: str = "",
    app_process_path: str | List[str] = "",
    selected_nics: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """根据用户规则动态构建 sing-box 配置字典。

    Args:
        rules: 规则列表，每项 {"process_name": [...], "outbound": "<tag>"}。
               兼容单字符串 process_name；非法/空规则会被安全跳过。
        default_outbound: 兜底出站标签（默认 aggregation 聚合叠加）。
        selected_nics: 用户选中的网卡列表（含 priority/alias 字段）。
               用于判定 UDP 出口网卡 — 取最高优先级 NIC 的 alias
               作为 bind_interface，未传入时 UDP 走系统默认路由。

    Returns:
        dict: 可直接 json.dump 的 sing-box 配置。
    """
    user_route_rules: List[Dict[str, Any]] = []
    for raw in (rules or []):
        rule = _normalize_rule(raw)
        if rule is not None:
            user_route_rules.append(rule)

    # ── UDP 出口选择：取最高优先级网卡的 alias 作为 bind_interface ──
    udp_outbound_tag = OUTBOUND_DIRECT
    udp_direct_outbound: Optional[Dict[str, Any]] = None
    if selected_nics:
        best = min(
            selected_nics,
            key=lambda n: int(n.get("priority", 1) or 1),
            default=None,
        )
        if best is not None:
            alias = str(best.get("name", best.get("alias", ""))).strip()
            if alias:
                udp_outbound_tag = OUTBOUND_UDP_PRIMARY
                udp_direct_outbound = {
                    "type": "direct",
                    "tag": OUTBOUND_UDP_PRIMARY,
                    "bind_interface": alias,
                }

    defensive_route_rules: List[Dict[str, Any]] = []
    defensive_route_rules.append({
        "action": "sniff",
        "timeout": "300ms",
    })
    app_paths: List[str] = []
    if isinstance(app_process_path, list):
        app_paths = [str(path).strip() for path in app_process_path if str(path).strip()]
    elif app_process_path:
        app_paths = [str(app_process_path).strip()]
    if app_paths:
        defensive_route_rules.append({
            "process_path": app_paths,
            "outbound": OUTBOUND_DIRECT,
        })
    defensive_route_rules.extend([
        {
            "process_name": [
                "HypoMux.exe",
                "main.exe",
                "python.exe",
                "pythonw.exe",
            ],
            "outbound": OUTBOUND_DIRECT,
        },
        {
            "process_name": [
                SINGBOX_EXE,
            ],
            "outbound": OUTBOUND_DIRECT,
        },
        {"port": [53], "action": "hijack-dns"},
        {"protocol": ["dns"], "action": "hijack-dns"},
    ])
    route_rules = defensive_route_rules + user_route_rules
    # UDP 兜底规则放在用户分流规则之后，确保分流优先级更高
    route_rules.append({"network": ["udp"], "action": "route", "outbound": udp_outbound_tag})

    dynamic_outbound_tags = []
    for rule in user_route_rules:
        tag = str(rule.get("outbound", ""))
        if tag.startswith("nic_") and tag not in (OUTBOUND_ETHERNET, OUTBOUND_WIFI):
            if tag not in dynamic_outbound_tags:
                dynamic_outbound_tags.append(tag)

    final_outbound = default_outbound if _is_valid_outbound_tag(default_outbound) else OUTBOUND_AGGREGATION

    outbounds = [
        _socks_outbound(OUTBOUND_ETHERNET, ethernet_port),
        _socks_outbound(OUTBOUND_WIFI, wifi_port),
        _socks_outbound(OUTBOUND_AGGREGATION, aggregation_port),
        {"type": "direct", "tag": OUTBOUND_DIRECT},
    ]
    if udp_direct_outbound is not None:
        outbounds.append(udp_direct_outbound)
    for tag in dynamic_outbound_tags:
        outbounds.append(_socks_outbound(tag, _dynamic_nic_port(tag)))

    dns_server_config: Dict[str, Any] = {
        "type": "local",
        "tag": DNS_LOCAL_TAG,
    }
    fakeip_server_config: Dict[str, Any] = {
        "type": "fakeip",
        "tag": DNS_FAKEIP_TAG,
        "inet4_range": "198.18.0.0/15",
    }
    dns_rules: List[Dict[str, Any]] = [{
        "query_type": ["A", "AAAA"],
        "server": DNS_FAKEIP_TAG,
    }]
    config: Dict[str, Any] = {
        "log": {"level": "warn", "timestamp": True},
        "dns": {
            "servers": [
                dns_server_config,
                fakeip_server_config,
            ],
            "rules": dns_rules,
            "final": DNS_LOCAL_TAG,
            "reverse_mapping": True,
        },
        "inbounds": [
            {
                "type": "tun",
                "tag": "tun-in",
                "interface_name": tun_name,
                "address": [TUN_ADDRESS],
                "mtu": 1492,
                "auto_route": True,
                "strict_route": True,
                "stack": "system",
            }
        ],
        "outbounds": outbounds,
        "route": {
            "auto_detect_interface": True,
            "default_domain_resolver": DNS_LOCAL_TAG,
            "final": final_outbound,
            "rules": route_rules,
        },
    }
    return config


def _normalize_rule(raw: Any) -> Optional[Dict[str, Any]]:
    """把任意来源的单条规则规整为合法的 sing-box route 规则；非法返回 None。"""
    if not isinstance(raw, dict):
        return None

    outbound = str(raw.get("outbound", "")).strip()
    if not _is_valid_outbound_tag(outbound):
        return None

    raw_proc = raw.get("process_name")
    procs: List[str] = []
    if isinstance(raw_proc, str):
        procs = [raw_proc.strip()] if raw_proc.strip() else []
    elif isinstance(raw_proc, list):
        procs = [str(p).strip() for p in raw_proc if str(p).strip()]
    if not procs:
        return None

    return {"process_name": procs, "outbound": outbound}


def write_config(
    config: Dict[str, Any],
    path: str | Path,
) -> bool:
    """把配置字典原子写入 config.json（先临时文件后替换）。

    Returns:
        bool: True 写入成功，False 失败（异常已被安全吞掉）。
    """
    try:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        tmp = target.with_suffix(".json.tmp")
        tmp.write_text(
            json.dumps(config, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        tmp.replace(target)
        logger.info(f"sing-box 配置已写入: {target}")
        return True
    except OSError as e:
        logger.warning(f"写入 sing-box 配置失败（IO/权限）: {e}")
        return False
    except Exception as e:
        logger.warning(f"写入 sing-box 配置发生未知异常: {e}")
        return False


def generate_config_file(
    rules: Optional[List[Dict[str, Any]]],
    path: str | Path,
    **kwargs,
) -> bool:
    """便捷入口：构建 + 写入一步到位。"""
    return write_config(build_config(rules, **kwargs), path)


def read_tun_gateway(config_path: str | Path = "") -> str:
    """从 singbox-config.json 提取 TUN 网关 IP，文件缺失/损坏时回退默认值。

    供路由清理代码使用：用户可能手动修改 config 中的 TUN 地址，
    清理残留路由时必须使用与 sing-box 实际运行一致的网关地址。
    """
    path = Path(config_path) if config_path else _default_config_path()
    if not path.is_file():
        return TUN_GATEWAY
    try:
        config = json.loads(path.read_text(encoding="utf-8"))
        addr = config["inbounds"][0]["address"][0]  # e.g. "172.19.0.1/30"
        return addr.split("/")[0]
    except Exception:
        return TUN_GATEWAY


def _default_config_path() -> Path:
    return Path.home() / ".hypomux" / "singbox-config.json"


def read_fakeip_range(config_path: str | Path = "") -> "ipaddress.IPv4Network":
    """从 singbox-config.json 提取 FakeIP 范围，文件缺失时回退默认值。

    sing-box fakeip 模式下 DNS 返回的假 IP 必须被 proxy_worker 过滤，
    否则应用会拿到不可路由的地址。默认范围 198.18.0.0/15。
    """
    path = Path(config_path) if config_path else _default_config_path()
    if not path.is_file():
        return ipaddress.IPv4Network("198.18.0.0/15")
    try:
        config = json.loads(path.read_text(encoding="utf-8"))
        for server in config.get("dns", {}).get("servers", []):
            if server.get("type") == "fakeip":
                return ipaddress.IPv4Network(server["inet4_range"])
    except Exception:
        pass
    return ipaddress.IPv4Network("198.18.0.0/15")
