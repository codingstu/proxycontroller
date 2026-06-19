# Proxy Controller 更新记录

本文档记录多地区主备双活引擎及后续可用性修复。部署入口为 `src/index.js`，`worker.js` 作为同步副本保留一致。

---

## 2026-06-19 - 强可用节点保活与自动补新

### 背景

面板中出现 JP 节点不可用后仍停留在 `STANDBY`、没有立即重新获取新 IP 的情况。旧逻辑主要检查当前 Active 通道，且补新依赖维护循环的单次候选选择；当备用通道失效、候选池枯竭或绑定状态残留时，容易形成“看起来有通道但业务出口不可用”的半死状态。

### 变更

- 健康检查覆盖每个 ready 通道，不再只检查 Active。
- 失败计数按 `region_idx + tunnel + entry_ip` 维度记录，连续 3 次失败后才判定不可用。
- Active 失败时立即拉黑旧 IP、清理通道、切换到可用 Standby，并触发补新。
- Standby 失败时不影响当前业务出口，只清理该备用并补齐新的热备通道。
- 新通道连上后仅在当前地区没有可用 Active 时才写入 `ACTIVE_BINDS`，避免新备用抢占业务出口。
- 新增 `_is_tunnel_live()`、`_clear_tunnel()`、`_select_active_tunnel_locked()` 等状态整理函数，统一处理通道存活、绑定修复和资源清理。
- 新增 `_trigger_emergency_harvest()` 和 `_emergency_harvest()`，在候选枯竭、拨号失败、TestISP/YouTube 质检失败、探针连续失败时立即补充节点快照。
- 候选池低于 4 个时提前收割；候选完全枯竭时只按国家范围兜底解锁黑名单，避免全局清空 `dead_ips`。
- 移除旧的 10 分钟全局清空黑名单逻辑，降低刚失败 IP 被快速选回的概率。

### 行为结果

- 每个地区持续尝试保持 1 个 Active + 1 个 Standby。
- 任一通道连续探针失败后会自动踢线、切换或补新，无需手动强制换 IP。
- 候选池不足时会主动刷新 VPNGate 快照，不再只等待 5 分钟定时抓取。

---

## 2026-06-15 - 清理死亡绑定与截图误提交

### `2a934e6` - 清理双通道死亡后的 `ACTIVE_BINDS`

当主备通道同时死亡时，旧逻辑可能保留 `ACTIVE_BINDS[port]` 指向已不存在的 TUN 设备名，导致 `SO_BINDTODEVICE` 绑定失败，代理连接被关闭。

修复点：

- `_maintain_region()` 在主备都不可用时清除对应端口绑定。
- `_force_switch_region()` 在备用也不可用时清除对应端口绑定。
- 新通道连上后由 `connect_node()` 重新设置正确绑定。

### `aa4af95` - 移除误提交截图

- 删除此前误提交的 `proxies_page.png` 和 `proxies_unauthorized.png`。
- 保持仓库只保留源码、文档和配置文件。

---

## 2026-06-15 - 多地区主备双活引擎

### 修改概述

本次修改将代理控制器从单地区主备双活架构升级为单 VPS 多地区主备双活架构，同时修复强制更换 IP 时直链提取 API 返回为空的问题。

### 强制更换 IP 熔断修复

旧代码收到 `switch_trigger` 指令时会同时杀死 `tun_main` 和 `tun_backup`，心跳上报 `details = []`，导致 `/api/proxies` 找不到活跃节点并返回空字符串。

修复后新增 `_force_switch_region()`：强制换 IP 时只清退当前活跃通道，备用通道继续承载业务。维护循环随后补充新的备用节点，避免强制换 IP 期间代理列表返空。

### 多地区架构改造

| 维度 | 旧架构 | 新架构 |
|------|--------|--------|
| 地区数 | 1 个，全局 `target_country` | N 个，`Region` 类动态管理 |
| 隧道命名 | `tun_main` / `tun_backup` | `tun_r{idx}m` / `tun_r{idx}b` |
| 路由表 | 101 / 102 | `200 + idx*100` / `201 + idx*100` |
| 代理端口 | 1 个全局端口 | 每地区独立端口，默认 7920 递增 |
| 绑定机制 | `ACTIVE_BIND` 单字符串 | `ACTIVE_BINDS` 字典 `{port: tun_name}` |
| 代理服务器 | 单端口监听 | 多端口 `select()` 监听 |
| 配置格式 | `{"0": "JP", "port": 7920}` | `{"regions": [{idx, country, port, switch_trigger}]}` |

### Agent 侧改造

- `Region` 类封装每个地区的国家、端口、强制换 IP 触发值和主备隧道。
- `reconcile_regions(desired)` 负责地区增删、国家变更、端口变更和强制换 IP。
- `_kill_region_tunnels(reg)` 和 `teardown_region(reg)` 负责地区级通道和路由清理。
- `_maintain_region(reg)` 负责单地区主备切换和补充。
- `get_best_candidate_for(country)` 按国家过滤候选节点，并排除各地区已占用 IP。

### proxy_server.py 改造

- `ACTIVE_BIND` 改为 `ACTIVE_BINDS = {}`。
- `create_connection()` 新增 `listen_port` 参数，按监听端口选择绑定的隧道接口。
- `socks5_client()`、`http_client()`、`proxy_client()` 全链路透传 `listen_port`。
- `start_proxy_server()` 改为多端口 `select()` 监听。

### 服务端 API 改造

- `GET /api/config` 返回 `{regions: [...]}`，并兼容旧配置格式。
- `POST /api/config` 接收 `regions` 数组并校验端口唯一性。
- `GET /api/proxies` 按 `region_idx` 分组，每个地区输出独立代理行。

### Dashboard UI 改造

- 单地区输入面板改为动态地区卡片列表。
- 每个地区卡片支持国家代码、端口、强制换 IP 和删除操作。
- 节点表格负载率改为动态通道数量显示。

---

## 修改文件说明

| 文件 | 说明 |
|------|------|
| `src/index.js` | Cloudflare Worker 入口，内嵌 `proxy_server.py`、`lite_manager.py`、API 和 Dashboard |
| `worker.js` | 与 `src/index.js` 保持一致的同步副本 |
| `README.md` | 部署说明、功能说明和卸载命令 |
| `CHANGELOG-multi-region.md` | 多地区和强可用更新记录 |

---

## 部署与验证

- 部署 Worker 后，VPS 需要重新运行 `/agent` 或手动重新拉取 `/scripts/lite_manager.py` 与 `/scripts/proxy_server.py`，再重启 `proxy-lite.service`。
- D1 数据库无需 Schema 变更，旧配置会自动兼容为 `regions` 格式。
- 建议通过 `journalctl -u proxy-lite.service -f` 观察：
  - Active 探针失败与秒切日志；
  - Standby 失败后的补齐日志；
  - 候选低水位或枯竭时的紧急收割日志。
