# 多地区主备双活引擎改造方案记录

## 修改概述

本次修改将代理控制器从**单地区主备双活**架构升级为**单 VPS 多地区主备双活**架构，同时修复了强制更换 IP 时直链提取 API 返回为空的熔断 Bug。

---

## Bug 修复：强制更换 IP 导致 API 返空

### 根因

旧代码 `update_config_loop` 在收到 `switch_trigger` 指令时，**同时杀死** `tun_main` 和 `tun_backup` 两个通道。心跳上报 `details = []`（空数组），`/api/proxies` 找不到活跃节点，返回空字符串。重新拨号需要 20-60 秒。

### 修复方案

新增 `_force_switch_region()` 函数：强制换 IP 时**仅杀死活跃通道**，保留备用通道继续承载业务流量。`maintain_pool` 每 2 秒检测到活跃通道死亡后自动互换身份、补充新备用节点。代理业务永不中断。

```python
def _force_switch_region(reg):
    active_name = proxy_server.ACTIVE_BINDS.get(reg.port, reg.main.name)
    active_tun = reg.main if active_name == reg.main.name else reg.backup
    standby_tun = reg.backup if active_tun == reg.main else reg.main
    # 仅杀活跃，备用保持
    ...
    if standby_tun.ready:
        proxy_server.ACTIVE_BINDS[reg.port] = standby_tun.name
```

---

## 多地区架构改造

### 核心设计

| 维度 | 旧架构 | 新架构 |
|------|--------|--------|
| 地区数 | 1 个（全局 `target_country`） | N 个（`Region` 类动态管理） |
| 隧道命名 | `tun_main` / `tun_backup` | `tun_r{idx}m` / `tun_r{idx}b` |
| 路由表 | 101 / 102 | `200 + idx*100` / `201 + idx*100` |
| 代理端口 | 1 个全局端口 | 每地区独立端口（默认 7920 递增） |
| 绑定机制 | `ACTIVE_BIND` 单字符串 | `ACTIVE_BINDS` 字典 `{port: tun_name}` |
| 代理服务器 | 单端口监听 | 多端口 `select()` 监听 |
| 配置格式 | `{"0": "JP", "port": 7920}` | `{"regions": [{idx, country, port, switch_trigger}]}` |

### 新增函数

- `Region` 类：封装单地区的 idx/country/port/switch_trigger 和 main/backup 隧道对
- `reconcile_regions(desired)`：协调地区增删，处理国家变更、端口变更、强制换 IP 触发
- `_force_switch_region(reg)`：仅杀活跃通道的安全换 IP
- `_kill_region_tunnels(reg)`：国家变更时杀掉该地区所有通道
- `teardown_region(reg)`：移除地区时清理隧道进程、路由表、ACTIVE_BINDS
- `_maintain_region(reg)`：单地区的主备故障切换 + 补充逻辑
- `_health_check_region(reg)`：单地区的多维探针健康检查
- `get_best_candidate_for(country)`：按国家过滤候选节点，排除所有地区已用 IP

### proxy_server.py 改造

- `ACTIVE_BIND` → `ACTIVE_BINDS = {}` 字典
- `create_connection` 新增 `listen_port` 参数，按端口查找绑定接口
- `socks5_client` / `http_client` / `proxy_client` 全链路透传 `listen_port`
- `start_proxy_server` 改为多端口 `select()` 监听器

### 服务端 API 改造

- `GET /api/config`：返回 `{regions: [...]}` 数组，向后兼容旧格式
- `POST /api/config`：接收 regions 数组，校验端口唯一性
- `GET /api/proxies`：按 `region_idx` 分组，每地区输出独立代理行

### Dashboard UI 改造

- 单地区输入面板 → 动态地区卡片列表
- 每个卡片：国家代码 + 端口 + 强制换 IP 按钮 + 删除按钮
- "添加地区" / "下发全部策略" 全局操作
- 节点表格负载率显示改为动态 `${count} 通道`

---

## 修改文件清单

| 文件 | 变更类型 | 说明 |
|------|----------|------|
| `src/index.js` | 重大修改 | proxy_server 模板、lite_manager 模板、API、Dashboard UI、Agent 脚本 |
| `worker.js` | 同步 | 与 src/index.js 完全一致 |
| `README.md` | 更新 | 功能说明、卸载命令适配新隧道命名 |

---

## 部署说明

- 部署入口：`src/index.js`（`wrangler.toml` 中 `main = "src/index.js"`）
- 一键部署按钮从 GitHub 仓库拉取代码，推送到 GitHub 后即可部署新代码
- 旧 Agent 重新运行 `/agent` 命令即可获得多地区版本
- D1 数据库无需 Schema 变更，旧配置自动迁移
