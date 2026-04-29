# Proxy Manager Service

Mihomo Multi Proxy 是一个专注于**决策能力外放**的代理管理服务。

与传统的一体化管理不同，本服务的核心理念是：**允许外部程序以它们喜欢的方式自主选择代理，而不是将负载均衡或选择逻辑强加于 Mihomo 服务本身。** Through stable port mapping, each proxy node is exposed as a unique local port, empowering external apps or scripts to handle the routing logic dynamically.

## ✨ 主要功能

*   **多源管理**：支持添加多种类型的代理源：
    *   **Subscription**: HTTP/HTTPS 订阅链接。
    *   **VLESS/URI**: 直接支持 `vless://`, `ss://`, `trojan://` 等URI链接。
    *   **Text/YAML**: 直接粘贴 Base64 或 YAML 格式的代理片段。
*   **稳定端口映射**：
    *   核心功能。系统使用 SQLite 数据库永久记录 `Proxy Name` <-> `Port` 的映射关系。
    *   即使订阅更新或重新排序，只要代理名称不变，分配的端口号就不会变。
    *   支持手动编辑端口号、删除映射。
    *   自动检测重复端口并发出警告。
*   **混合端口模式**：所有生成的端口均采用 `mixed` 模式 (同时支持 HTTP 和 SOCKS5)。
*   **Web 可视化管理**：通过现代化 Web 界面管理所有配置。
*   **一键生效**：支持自动生成 `config.yaml` 并调用 `systemctl restart mihomo` 重启服务。
*   **WireGuard / ProtonVPN 导入**：
    *   支持直接导入 WireGuard `.conf` 或包含 `wireguard_configs` 的 JSON/YAML。
    *   ProtonVPN source 支持在线拉取服务器列表，拉取后会保存为 WireGuard 配置和可刷新会话，不保存 Proton 密码或 OTP。
    *   ProtonVPN 默认按真实 WireGuard endpoint 去重，把多个逻辑服务器编号合并为一个可连接节点。
    *   新增节点预览与选择，只导入你勾选的服务器，生成配置时仍保持每个节点一个稳定端口。

## 📂 目录结构

```
mihomo-multi-proxy/
├── main.py              # FastAPI 后端入口
├── database.py          # SQLite 数据库管理
├── config_generator.py  # 配置文件生成核心逻辑
├── proxy_parser.py      # 代理链接/订阅解析器 (含 VLESS 支持)
├── static/              # Vue.js 前端资源
├── deploy.sh            # Linux 自动部署脚本
└── proxy-manager.service # Systemd 服务文件
```

## 📦 安装 Mihomo (Clash Meta)

本服务依赖 Mihomo (原 Clash Meta) 运行。如果在 Linux 服务器上部署，请先安装 Mihomo。

### 1. 下载与安装

从 [GitHub Releases](https://github.com/MetaCubeX/mihomo/releases) 下载适合即架构的版本 (如 `mihomo-linux-amd64`):

```bash
# 下载 (以 v1.17.0 为例，请检查最新版本)
wget https://github.com/MetaCubeX/mihomo/releases/download/v1.17.0/mihomo-linux-amd64-v1.17.0.gz

# 解压
gzip -d mihomo-linux-amd64-v1.17.0.gz

# 安装
sudo mv mihomo-linux-amd64-v1.17.0 /usr/local/bin/mihomo
sudo chmod +x /usr/local/bin/mihomo

# 创建配置目录
sudo mkdir -p /etc/mihomo
```

### 2. 配置 Systemd 服务

创建服务文件 `/etc/systemd/system/mihomo.service`:

```ini
[Unit]
Description=Mihomo Daemon, another Clash Kernel.
After=network.target NetworkManager.service systemd-networkd.service iwd.service

[Service]
Type=simple
LimitNPROC=500
LimitNOFILE=1000000
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE
Restart=always
ExecStartPre=/usr/bin/sleep 1s
ExecStart=/usr/local/bin/mihomo -d /etc/mihomo
ExecReload=/bin/kill -HUP $MAINPID

[Install]
WantedBy=multi-user.target
```

### 3. 启动并开机自启

```bash
sudo systemctl enable mihomo
sudo systemctl start mihomo
sudo systemctl enable mihomo
sudo systemctl start mihomo
```

### 4. 配置 UI 界面 (MetaCubeXD)

Proxy Manager 默认生成的配置启用了外部控制功能。为了使用 MetaCubeXD 面板，请执行以下命令安装 UI 文件：

```bash
# 进入配置目录
cd /etc/mihomo

# 下载 MetaCubeXD (使用 gh-pages 分支)
# 方式 1: 使用 git (推荐)
sudo git clone -b gh-pages https://github.com/MetaCubeX/metacubexd.git dashboard

# 方式 2: 下载压缩包
# sudo wget https://github.com/MetaCubeX/metacubexd/archive/refs/heads/gh-pages.zip
# sudo unzip gh-pages.zip
# sudo mv metacubexd-gh-pages dashboard
```

安装完成后，你可以通过以下地址访问 Clash 面板：
*   **地址**: `http://<服务器IP>:9090/ui`
*   **API Secret**: `orzboost` (默认配置)

**注意**：Proxy Manager 会自动生成 `/etc/mihomo/config.yaml` 并重启此服务，因此你只需确保服务已正确安装且 `systemctl restart mihomo` 命令可用。

**注意**：Proxy Manager 会自动生成 `/etc/mihomo/config.yaml` 并重启此服务，因此你只需确保服务已正确安装且 `systemctl restart mihomo` 命令可用。

### 1. 准备工作

确保服务器已安装 Python 3 和 pip。建议使用 root 或有 sudo 权限的用户。

### 2. 自动部署

上传 `mihomo-multi-proxy` 文件夹到服务器后，运行部署脚本：

```bash
cd mihomo-multi-proxy
chmod +x deploy.sh
sudo ./deploy.sh
```

此脚本会自动：
1.  创建安装目录 `/opt/proxy-manager`。
2.  安装 Python 依赖 (`fastapi`, `uvicorn`, `pyyaml`, 等)。
3.  注册并启动 `proxy-manager` 系统服务。

### 3. 手动部署

如果不使用脚本，可手动执行：

```bash
# 1. 移动文件
sudo mkdir -p /opt/proxy-manager
# 将代码放入子目录 mihomo-multi-proxy 以匹配 invoke 路径
sudo mkdir -p /opt/proxy-manager/mihomo-multi-proxy
sudo cp -r ./* /opt/proxy-manager/mihomo-multi-proxy/
cd /opt/proxy-manager

# 2. 安装依赖 (使用虚拟环境)
sudo python3 -m venv venv
sudo ./venv/bin/pip install -r mihomo-multi-proxy/requirements.txt

# 3. 配置服务
# 注意: proxy-manager.service 已默认配置为使用上述 venv
sudo cp mihomo-multi-proxy/proxy-manager.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable proxy-manager
sudo systemctl start proxy-manager
```

### 4. 访问与配置

*   **访问地址**: `http://<服务器IP>:8080` (默认端口，可在 server 文件中修改)
*   **配置输出路径**: 在网页控制台右侧，填写你的 mihomo 配置文件路径，例如 `/etc/mihomo/config.yaml`。
*   **重启服务权限**: 
    *   服务默认以 ROOT 运行以获取写入配置和重启服务的权限。
    *   如果需要重启 Mihomo，请确保 `systemctl restart mihomo` 命令有效。

### ProtonVPN 在线拉取

在新增或编辑 Source 时选择 `Proton`：

*   `Password` 模式：输入 Proton 账号、密码和可选 2FA code，服务会通过 Proton API 拉取可用 WireGuard 节点。
*   `Session` 模式：如果账号登录流程被验证码、设备确认或 FIDO2 卡住，可以从浏览器请求里复制 Cookie / `x-pm-uid` / `AUTH` token / `AccessToken` 进行一次性拉取。

通过账号密码拉取成功后，source 会保存 Proton 返回的 refresh token；之后编辑该 Proton source 时可以直接点击 Fetch 刷新服务器列表，不需要再次输入 OTP。Proton 密码和 OTP 不会落库，但 refresh token 具备账号会话权限，请把数据库文件按敏感配置保护。

Proton API 可能返回大量不同逻辑编号但相同 `server + port + public-key` 的 WireGuard 入口。服务默认会按这个 endpoint 去重，预览中会显示去重后的 endpoint 数量和合并前的逻辑节点数量；如需保留 Proton 原始逻辑节点，可在 Proton 拉取面板勾选保留重复逻辑节点。

## 🛠 开发与调试

本地运行测试：

```powershell
uvicorn mihomo-multi-proxy.main:app --host 0.0.0.0 --port 18000 --reload
```

## ⚠️ 注意事项

*   **唯一标识**：端口映射依赖于 **Proxy Name**。如果机场修改了节点名称，系统会将其视为新节点并分配新端口。
*   **VLESS 支持**：内置了 VLESS 解析器，支持 Reality 和 Vision 流控配置。
