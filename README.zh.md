<p align="center">
  <a href="docs/assets/gedefense-logo.png">
    <img src="docs/assets/gedefense-logo.png" alt="GeDefense Retail" width="360">
  </a>
</p>

<h1 align="center">GeDefense Retail</h1>

<p align="center"><strong>ColdChain &amp; Store Infrastructure Security</strong><br>
面向门店管理路径的被动 OT 监控与 Default-Deny 执行。</p>

<p align="center">
  <a href="https://github.com/visiongaiatechnology/gedefense-retail/releases"><img alt="版本" src="https://img.shields.io/github/v/release/visiongaiatechnology/gedefense-retail?style=flat-square&label=release"></a>
  <img alt="许可证: AGPL-3.0" src="https://img.shields.io/badge/license-AGPL--3.0-blue?style=flat-square">
  <img alt="Go 1.23+" src="https://img.shields.io/badge/go-1.23%2B-00ADD8?style=flat-square&logo=go&logoColor=white">
  <img alt="平台: Linux 与 Windows" src="https://img.shields.io/badge/platforms-Linux%20%7C%20Windows-444?style=flat-square">
  <img alt="状态: Alpha" src="https://img.shields.io/badge/status-alpha-orange?style=flat-square">
</p>

[English](README.md) · [Deutsch](README.de.md) · [Français](README.fr.md) · [Italiano](README.it.md) · [Español](README.es.md) · [日本語](README.ja.md) · [中文](README.zh.md) · [Русский](README.ru.md)

---

<a id="alpha-status"></a>
## Alpha 状态

> **0.2.0-alpha.4 — 实验性版本，尚未达到生产可用。**
> GeDefense Retail 是早期 Alpha 版本。验证仅在回环环境中针对模拟控制器和模拟管理器完成，并未
> 针对门店中真实的制冷硬件进行。目前还没有针对 Access Gate 的独立渗透测试，也不作出任何合规或
> 认证声明。请勿将其用作制冷设备唯一的安全、食品安全或监控控制手段。

<a id="overview"></a>
## 这是什么

GeDefense Retail 保护并记录超市背后的基础设施：制冷控制器、冷库、冷藏陈列柜、传感器网关、楼宇
自动化，以及制冷服务公司使用的远程维护路径。

它以两个相互独立的服务形式提供：

| 服务 | 二进制 | 作用 |
|---|---|---|
| **监控** | `retaild` | 被动、只读的 OT 可观测性：资产、流量、冷链完整性、数据质量、告警、审计、仪表板 |
| **Access Gate** | `retailgate` | 通往控制器的管理/配置写入的唯一允许路径：Default-Deny、绑定计划、人工审批、完整审计 |
| **模拟器** | `retail-sim` | 用于开发和验收测试的本地测试数据（仅回环） |

**产品承诺：**

- **GeDefense 不提供任何 OT 过程写入路径。** `retaild` 及所有被动适配器永远不会写入控制器。
  Access Gate 不控制过程；它只授权并转发一个经过明确批准的配置操作。
- **写入采用 Default-Deny。** 只有当写入与已批准的 *Write-Plan*（目标、协议、功能、地址**和**值）
  完全匹配，且处于已批准的时间窗口内时，才会被转发。
- **人工控制。** 关键资产需要两个不同的审批，其中之一必须来自 `master_admin`。不存在自主写入、
  基于计划的写入或 AI 决策。
- **管理路径采用 Fail-closed。** 若 Access Gate 停止，远程管理即被关闭。制冷设备会继续自主运行，
  因为 Access Gate 不在过程回路中。
- **先留证据，后产生效果。** 每个操作和每次被拒绝的写入都会写入哈希链审计日志；若链已损坏，
  Access Gate 将拒绝启动。

<a id="features"></a>
## 功能

### ColdChain 监控（`retaild`，被动/只读）

- 基于流量元数据、OUI 线索和协议证据的被动资产发现——未知设备保持未知，并附带置信度数值。
- OT 网络观测：新的通信对端、异常路径、协议元数据、流量基线。
- 冷链完整性：由运营方定义的温度上限、变化率、设定值偏差、独立传感器之间的偏差。
- 数据质量检查：数值冻结、遥测缺失、时钟偏移、不合理数值——不良读数绝不会被显示为合格温度。
- 维护访问：已批准的时间窗口、供应商访问异常、会话元数据。
- 检测规则与关联事件：每条告警中，事实、假设和建议的检查始终保持分离。
- 本地优先运行：检测与告警在无 WAN 的情况下继续工作；提供有界本地缓冲以便后续转发。
- 哈希链审计、基于角色的 API 访问、玻璃质感仪表板、无外部 CDN、无第三方前端框架。
- 适用于 Modbus TCP、MQTT、BACnet/IP、SNMP（v1/v2c GET）、PCAP 以及 HTTP 管理 UI 元数据的
  被动/只读适配器。

### Access Gate（`retailgate`，Default-Deny 执行）

- Write-Plan 包含当前值、新值、原因、工单引用（可选）、时间窗口以及不可变的计划哈希。
- 审批工作流支持 MFA（本 Alpha 中为 TOTP）、幂等审批、禁止自我审批，关键资产采用四眼原则。
- 一次性令牌与绑定源 IP 的写入会话；重放、过期和来源错误的尝试都会被拒绝并触发告警。
- Modbus TCP 执行代理以及面向管理器 Web UI 的 HTTP(S) 反向代理。
- 寄存器与 URL 允许列表；允许列表是必要条件但非充分条件——已批准的计划也必须精确匹配。
- Deny 时间线、拒绝证据以及对每次被拒写入的审计。
- Fail-safe 矩阵：存储/审计错误、时钟跳变和无效策略会关闭写入路径；Access Gate 失效不会影响设备。
- HMAC 签名的 Webhook 通知，支持升级与确认（`GET /escalations`、
  `POST /escalations/{id}/ack`）。

### 0.2.0-alpha.2 中的新功能

- **设置向导**（首次运行，仅回环），引导完成语言、站点、访问允许列表、管理员账户、采集器与完成
  步骤。
- **IP 允许列表**在配置后对仪表板、API、SSE、静态资源及设置生效（`require_whitelist` 默认开启，
  fail-closed）。
- **八种 UI 语言**：英语、德语、法语、意大利语、西班牙语、日语、中文、俄语。
- **原始 GeDefense 标志**与吉祥物作为本地资源集成（无外部 CDN）。
- 提供 Linux 和 Windows 软件包，包含安装脚本与 SHA-256 校验和。

<a id="architecture"></a>
## 架构（概要）

```text
 服务公司 / 运营方
 (VPN / ZTNA，已列入允许列表)
        │
        ▼
 ┌──────────────────────────────┐        ┌──────────────────────────────┐
 │ retaild（监控）               │        │ retailgate（执行）            │
 │ 被动 TAP/SPAN、只读           │        │ 身份、审批、令牌              │
 │ 检测、告警、审计、UI          │        │ 审计、Modbus/HTTP 代理        │
 └──────────────┬───────────────┘        └──────────────┬───────────────┘
                │ 被动观测                                │ 仅管理路径
                │（从不写入）                            │（绑定计划、Default-Deny）
                ▼                                        ▼
        OT 监控网段                               控制器 / 管理器
        （TAP/SPAN，只读轮询）                    （Modbus TCP、HTTP(S) 管理 UI）
```

- 每个门店一台网关；本地运行不依赖互联网。
- Access Gate 以**具有两个网络接口的独立设备/VM**部署：管理/供应商侧与 OT 管理导管。它不是路由器，
  也不位于控制器与执行器之间的过程通信中。
- 可选的集中管理为仅出站（mTLS）。

<a id="alpha-limitations"></a>
## 关于 Alpha 的坦诚限制

- **尚未测试真实 OT 硬件。** 数据平面证据来自回环环境中的模拟控制器与模拟管理器。真实的单元 ID、
  供应商登录流程、证书和固件状态属于试点议题。
- **TOTP 不是抗钓鱼因素。** FIDO2/WebAuthn 计划在后续版本中提供；本 Alpha 因素不作出任何抗性声明。
- **分段是运营方的职责。** 如果没有真实的“无第二条路径”网络设计，Access Gate 是可被绕过的。监控服务让绕过
  行为可见，但无法阻止它们。
- **没有自动绕过关联。** Access Gate 与监控服务相互独立；本 Alpha 中被拒绝的写入与被动
  `retail.write-attempt` 告警需人工关联。
- **证书固定与参数允许列表**已在代理中实现，但尚未在配置模式中暴露。
- **`write_unknown` 没有自动回读。** 若控制器响应不明确（超时、断开），该写入会被标记为
  `write_unknown` 并产生严重告警；运营方必须通过回读核实数值，并**不得自动重试**。
- **API 会话保存在内存中。** 重启会注销用户；这是有意的 fail-closed 行为。
- **没有 BACnet/MQTT 数据平面，也没有供应商云/本地 HMI/USB 控制。** 这些超出本 Alpha 范围，仍属
  运营方议题。
- **不作合规声明。** GeDefense Retail 不声称符合 HACCP、NIS2、IEC 62443 或任何其他认证。
- **Windows 权限与 Linux 不同。** POSIX `0600/0700` 在 Windows 上不是访问控制机制；请使用专用服务
  账户和显式 ACL。这是已记录的 Beta 条件。

<a id="download"></a>
## 下载

**最新 Alpha 版本：[v0.2.0-alpha.4](https://github.com/visiongaiatechnology/gedefense-retail/releases/tag/v0.2.0-alpha.4)。**
资源：四个归档、[SHA256SUMS](https://github.com/visiongaiatechnology/gedefense-retail/releases/download/v0.2.0-alpha.4/SHA256SUMS)、
[SHA256SUMS.archives](https://github.com/visiongaiatechnology/gedefense-retail/releases/download/v0.2.0-alpha.4/SHA256SUMS.archives)、
[SBOM.spdx.json](https://github.com/visiongaiatechnology/gedefense-retail/releases/download/v0.2.0-alpha.4/SBOM.spdx.json)
以及 cosign 签名（`*.sig`/`*.pem`）。Windows 二进制为 **NOT_SIGNED**（Authenticode，Alpha）；请使用哈希/签名。

| 平台 | 归档 | 校验和 |
|---|---|---|
| Linux amd64 | [gedefense-retail-0.2.0-alpha.4-linux-amd64.tar.gz](https://github.com/visiongaiatechnology/gedefense-retail/releases/download/v0.2.0-alpha.4/gedefense-retail-0.2.0-alpha.4-linux-amd64.tar.gz) | [SHA256SUMS](https://github.com/visiongaiatechnology/gedefense-retail/releases/download/v0.2.0-alpha.4/SHA256SUMS) · [归档](https://github.com/visiongaiatechnology/gedefense-retail/releases/download/v0.2.0-alpha.4/SHA256SUMS.archives) |
| Linux arm64 | [gedefense-retail-0.2.0-alpha.4-linux-arm64.tar.gz](https://github.com/visiongaiatechnology/gedefense-retail/releases/download/v0.2.0-alpha.4/gedefense-retail-0.2.0-alpha.4-linux-arm64.tar.gz) | [SHA256SUMS](https://github.com/visiongaiatechnology/gedefense-retail/releases/download/v0.2.0-alpha.4/SHA256SUMS) · [归档](https://github.com/visiongaiatechnology/gedefense-retail/releases/download/v0.2.0-alpha.4/SHA256SUMS.archives) |
| Windows amd64 | [gedefense-retail-0.2.0-alpha.4-windows-amd64.zip](https://github.com/visiongaiatechnology/gedefense-retail/releases/download/v0.2.0-alpha.4/gedefense-retail-0.2.0-alpha.4-windows-amd64.zip) | [SHA256SUMS](https://github.com/visiongaiatechnology/gedefense-retail/releases/download/v0.2.0-alpha.4/SHA256SUMS) · [归档](https://github.com/visiongaiatechnology/gedefense-retail/releases/download/v0.2.0-alpha.4/SHA256SUMS.archives) |
| Windows arm64 | [gedefense-retail-0.2.0-alpha.4-windows-arm64.zip](https://github.com/visiongaiatechnology/gedefense-retail/releases/download/v0.2.0-alpha.4/gedefense-retail-0.2.0-alpha.4-windows-arm64.zip) | [SHA256SUMS](https://github.com/visiongaiatechnology/gedefense-retail/releases/download/v0.2.0-alpha.4/SHA256SUMS) · [归档](https://github.com/visiongaiatechnology/gedefense-retail/releases/download/v0.2.0-alpha.4/SHA256SUMS.archives) |

**安装前校验：** 在解压包内执行 `sha256sum -c SHA256SUMS`，对下载的归档执行
`sha256sum -c SHA256SUMS.archives`。归档和 `SHA256SUMS` 使用 cosign keyless 签名；使用
`cosign verify-blob --certificate <file>.pem --signature <file>.sig
--certificate-oidc-issuer https://token.actions.githubusercontent.com
--certificate-identity-regexp 'https://github.com/visiongaiatechnology/gedefense-retail/.github/workflows/release.yml@refs/tags/v.*' <file>` 验证（确切身份见
[docs/BUILD-AND-RELEASE.md](docs/BUILD-AND-RELEASE.md)）。`SBOM.spdx.json` 是 SPDX 组件清单。
**若缺少签名文件，请将该下载视为未签名。**

每个包包含 `bin/`（二进制文件）、`config/`（示例配置与 systemd 单元）、`docs/`、`README.md`、
`LICENSE`、`VERSION`、`THIRD-PARTY-NOTICES.md`、安装脚本以及 `SHA256SUMS` 文件。

<a id="install-linux"></a>
## 安装 — Linux

**前提条件**

- 具备 systemd 的 Linux x86-64 或 arm64。
- 安装需要管理员权限。
- 位于计划允许列表 CIDR 内的管理客户端（设置期间为回环）。
- 二进制软件包不需要 Go 工具链。
- 在启用远程访问**之前**，请先规划允许列表与 OT/管理分段。

**1. 下载并校验**

```bash
tar -xzf gedefense-retail-<version>-linux-amd64.tar.gz
cd gedefense-retail-<version>-linux-amd64
sha256sum -c SHA256SUMS
```

**2. 安装**

```bash
sudo ./install.sh
```

安装程序创建服务账户，从 `config/` 安装 systemd 单元（`gedefense-retail.service`、
`gedefense-retailgate.service`），准备 `/etc/gedefense-retail/`、`/var/lib/gedefense-retail/`、
`/var/lib/gedefense-gate/` 和 `/var/log/gedefense-retail/`，并使监控服务准备好进行首次运行设置。
它**仅复制示例配置**（`retail.example.json`、`gate.example.json`、`gate-policy.example.json`），
绝不覆盖现有文件。配置以 `root:gedefense` 安装（`0750` 目录、`0640` 文件），数据目录归服务账户所有；
若权限步骤失败，安装程序将中止（fail-closed）。运营方基于示例创建生产配置：

```bash
sudo cp /etc/gedefense-retail/retail.example.json /etc/gedefense-retail/retail.json
# 编辑 retail.json：站点、用户、采集器、安全允许列表、网关目标/上游
```

**3. 首次运行设置（仅回环）**

```bash
sudo systemctl enable --now gedefense-retail
```

当 `setup.completed=false` 时，首次启动**仅绑定回环**（为下方 URL 将 `listen` 配置为
`127.0.0.1:8080`）。请在网关本机上打开 `http://127.0.0.1:8080/setup`（SSH 隧道或本地浏览器），完成
向导：语言、站点/时区、访问允许列表（例如 `127.0.0.1/32`、`::1/128` 加上您的管理 CIDR）、管理员
令牌（**只显示一次**）、可选的采集器、完成（`restart_required: true`）。
`security.setup_token_ttl_s` 默认值为 3600 秒。允许列表采用 fail-closed：没有条目时，非回环客户端
会收到 `403 ip_not_allowed`，且不会暴露登录页面。

```bash
sudo systemctl restart gedefense-retail
```

**4. 校验**

```bash
systemctl status gedefense-retail --no-pager
retaild version
curl -s http://127.0.0.1:8080/api/v1/health
```

只有位于 `security.dashboard_whitelist_cidrs` 内的源 IP 才能访问仪表板、API、SSE 和静态资源。来自
允许列表之外的请求会收到 `403 ip_not_allowed`；不存在备用登录页面。

**5. 可选：启用 Access Gate**

请在监控设置完成后再启用 Access Gate。它需要 `gate.json` **和** `gate-policy.json`；若没有有效的
配置和策略，将拒绝启动（fail-closed）。

```bash
sudo cp /etc/gedefense-retail/gate.example.json /etc/gedefense-retail/gate.json
sudo cp /etc/gedefense-retail/gate-policy.example.json /etc/gedefense-retail/gate-policy.json
# 编辑两个文件：目标、用户、允许列表、关键资产、允许列表
sudo retailgate hash-password --password "<at least 12 characters>"
sudo retailgate gen-totp
# 将打印的密码哈希和 TOTP 密钥填入 gate.json，然后校验并启动：
sudo -u gedefense-gate retailgate check --config /etc/gedefense-retail/gate.json
sudo systemctl enable --now gedefense-retailgate
```

Access Gate 必须运行在独立的双网卡设备/VM 上（管理侧与 OT 管理导管），而不是运行在监控主机上。若
分段不正确，Access Gate 可被绕过。

<a id="install-windows"></a>
## 安装 — Windows

**前提条件**

- Windows 10/11 或 Windows Server 2019+（x64 或 arm64），PowerShell 5.1+。
- 管理员权限。
- 位于计划允许列表 CIDR 内的管理客户端；设置仅通过回环执行。

**1. 下载、解压、校验**

```powershell
Expand-Archive .\gedefense-retail-<version>-windows-amd64.zip -DestinationPath .
cd .\gedefense-retail-<version>-windows-amd64
Get-FileHash .\bin\retaild.exe -Algorithm SHA256
# 与 SHA256SUMS 中的值（包内所有文件）进行比较
```

**2. 安装**

```powershell
# 具有管理员权限的 PowerShell
.\install-windows.ps1
```

安装程序创建程序目录 `C:\Program Files\GeDefense\Retail\`（包含 `bin\` 和 `config\`）、数据目录
`C:\ProgramData\GeDefense\Retail\`，并通过 `sc.exe`（`gedefense-retail`、`gedefense-retailgate`）
注册 Windows 服务。它**仅复制示例配置**；运营方基于 `config\` 中的示例创建生产文件 `retail.json` /
`gate.json`。**不会自动创建防火墙规则**——请仅添加实际需要的允许列表和管理端口。

**3. 首次运行设置**

```powershell
Start-Service gedefense-retail
```

在网关上打开 `http://127.0.0.1:8080/setup`（将 `listen` 设置为 `127.0.0.1:8080`），完成六个设置
步骤，然后重启：

```powershell
Restart-Service gedefense-retail
Get-Service gedefense-retail
.\bin\retaild.exe version
```

**Windows 权限（Alpha）：** 安装程序以 `NT AUTHORITY\LocalService` 运行两个服务，并设置禁用继承的
显式 `icacls` DACL：`config\` 为读取、`C:\ProgramData\GeDefense\Retail\` 为修改，Administrators 完全
控制，`Users` 无访问权限。POSIX 模式不能保护 NTFS；不要重新启用继承 ACL。卸载不会恢复之前的 ACL。

**4. 可选：Access Gate**

```powershell
# 配置示例：C:\Program Files\GeDefense\Retail\config\gate.example.json / gate-policy.example.json
# 生产文件：...\config\gate.json 与 ...\config\gate-policy.json（编辑目标/用户/允许列表）
.\bin\retailgate.exe hash-password --password "<at least 12 characters>"
.\bin\retailgate.exe gen-totp
# 将打印的密码哈希和 TOTP 密钥填入 gate.json，然后校验并启动：
.\bin\retailgate.exe check --config "C:\Program Files\GeDefense\Retail\config\gate.json"
Start-Service gedefense-retailgate
```

Access Gate 需要两个配置文件，且在没有有效策略时会拒绝启动（fail-closed）。请在独立的双网卡设备/VM
上运行；Windows 安装程序不会配置分段或防火墙规则。

<a id="quickstart"></a>
## 快速开始

1. 安装适用于您平台的软件包。
2. 启动监控服务并完成回环设置向导。
3. 至少向允许列表添加一个管理客户端 CIDR——否则所有非回环请求都会被拒绝。
4. 使用向导只显示一次的管理员令牌登录仪表板。
5. 用于模拟或开发时，请在网关上运行 `retail-sim`（仅回环，需要模拟标志）——切勿针对生产 OT 设备运行。

从源码构建（开发者，Go 1.23+，仅标准库，无 CGO）：

```bash
go build ./...
go vet ./...
go test ./...
```

<a id="security"></a>
## 安全模型

- **只读监控。** `retaild` 没有 OT 写入路径。被动适配器从不发送写入功能码，从不执行主动扫描，也从
  不发送原始探测。
- **Default-Deny 管理路径。** `retailgate` 仅转发与已批准计划完全匹配的操作；其余一切都会被拒绝、
  审计并告警。
- **精确绑定。** 目标、协议、功能、地址和值作为一个整体获得批准。即使在已批准的时间窗口内，不同的
  值或地址也会被拒绝。
- **人工审批。** 拒绝自我审批；关键资产需要两位不同的审批人，其中包含一位 `master_admin`。一次性
  令牌只显示一次，并绑定到计划哈希与源 IP。
- **先审计后生效。** 被拒绝和被允许的操作都会写入哈希链审计日志；若链已损坏，Access Gate 将拒绝启动。
- **Fail-closed。** Access Gate、存储、时钟或策略问题会关闭管理路径；设备继续运行。
- **网络。** 允许列表执行采用 fail-closed。请勿将仪表板或 Access Gate 暴露到互联网；如需远程访问，请使用
  VPN/ZTNA 路径并记录代理设置。
- **报告。** 请按照 [SECURITY.md](SECURITY.md) 所述以保密方式报告漏洞。请勿针对生产制冷设备进行测试。
- **不作合规声明。** 请参阅 [SECURITY.md](SECURITY.md) 与 [NOTICE](NOTICE)。

<a id="evidence"></a>
## 验证状态（如实说明）

| 领域 | 状态 |
|---|---|
| 构建、vet、单元/集成测试、竞态检测器 | 通过（回环/CI） |
| 0.1 端到端验收（监控） | 39/39 项检查通过（回环/模拟） |
| 0.2.0-alpha.1 Access Gate 端到端 | 25/25 项检查通过（回环、模拟控制器） |
| 设计 QA | 已生成模拟数据截图；未进行屏幕阅读器/触控/长时间运行验证 |
| 真实 OT 硬件 | 尚未测试（试点议题） |
| 独立的 Access Gate 渗透测试 | 尚不可用 |
| 合规/认证 | 未作任何声明 |

相关数字来自发布说明中描述的验证运行，并不构成生产就绪声明。

<a id="documentation"></a>
## 文档

- [README (English)](README.md) · [README (Deutsch)](README.de.md)
- [SECURITY.md](SECURITY.md) — 报告、Alpha 状态、范围
- [CONTRIBUTING.md](CONTRIBUTING.md) — 构建、测试、安全不变量、拉取请求
- [CHANGELOG.md](CHANGELOG.md) — 发布历史
- [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md) — 依赖与资源
- [NOTICE](NOTICE) — 版权与许可声明
- [LICENSE](LICENSE) — GNU Affero General Public License v3.0
- [文档索引](docs/README.md)
- [Releases](https://github.com/visiongaiatechnology/gedefense-retail/releases) ·
  [Issues](https://github.com/visiongaiatechnology/gedefense-retail/issues)

<a id="license"></a>
## 许可证

GeDefense Retail 依据 **GNU Affero General Public License v3.0**（AGPL-3.0）授权。
请参阅 [LICENSE](LICENSE) 与 [NOTICE](NOTICE)。

Copyright © 2026 VisionGaiaTechnology.
