# 🌀 Vane

> 轻量级网络服务管理工具 — 端口转发 · DDNS · Web服务 · TLS证书

[![Build](https://github.com/yourusername/vane/actions/workflows/build.yml/badge.svg)](https://github.com/yourusername/vane/actions)

---

## ✨ 功能特性

| 模块 | 功能 |
|------|------|
| 🔵 **端口转发** | TCP/UDP 端口转发，实时流量监控 |
| 🟢 **DDNS** | 动态域名，支持 Cloudflare / 阿里云 / DNSPod / 腾讯云 |
| 🟣 **Web 服务** | 反向代理，HTTP → HTTPS，多域名多后端 |
| 🟠 **TLS 证书** | Let's Encrypt DNS-01 自动申请续期 + 手动上传 |

## 🚀 快速开始

```bash
# 下载二进制
wget https://github.com/yourusername/vane/releases/latest/download/vane-linux-amd64
chmod +x vane-linux-amd64

# 运行
./vane-linux-amd64

# 访问管理界面
# http://your-ip:4455
# 默认账号: admin / vane1234  （请及时修改密码）
```

## 🏗️ 从源码构建

```bash
# 1. 构建前端
cd web && npm install && npm run build && cd ..

# 2. 构建 Go 二进制
go build -o vane .

# 3. 运行
./vane
```

## 📦 项目结构

```
vane/
├── main.go              # 入口
├── config/              # 配置管理 (vane.json)
├── module/
│   ├── portforward/     # 端口转发
│   ├── ddns/            # DDNS
│   ├── webservice/      # 反向代理
│   └── tls/             # 证书管理
├── api/                 # REST API
├── web/                 # Vue3 前端
└── .github/workflows/   # CI/CD
```

## ⚙️ 配置文件

首次运行自动创建 `vane.json`，所有配置通过 Web 界面管理。

## 📄 License

MIT
