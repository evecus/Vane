# Vane (Rust)

Vane 的 Rust 重写版本。单一二进制，内嵌前端，零外部依赖。

## 功能

- **端口转发** — TCP / UDP，带流量统计
- **DDNS** — Cloudflare，自动检测公网 IP
- **反向代理** — 域名路由，SNI TLS，Basic Auth
- **TLS 证书** — ACME DNS-01（Let's Encrypt / ZeroSSL）自动申请与续签
- **IP 过滤** — 白名单 / 黑名单，支持 CIDR
- **配置加密** — AES-256-GCM 本地加密存储（SQLite bundled）

## 构建

### 前置条件

- Rust 1.80+
- Node.js 20+（构建前端）

### 本地构建

```bash
# 构建前端
cd web && npm ci && npm run build && cd ..

# 构建 release 二进制（当前平台）
cargo build --release

# 交叉编译 amd64 musl（静态链接）
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl

# 交叉编译 arm64 musl
rustup target add aarch64-unknown-linux-musl
# 需要: apt install gcc-aarch64-linux-gnu musl-tools
# 并在 .cargo/config.toml 中配置 aarch64 链接器
cargo build --release --target aarch64-unknown-linux-musl
```

### .cargo/config.toml（arm64 交叉编译）

```toml
[target.aarch64-unknown-linux-musl]
linker = "aarch64-linux-gnu-gcc"
```

## 运行

```bash
./vane                        # 数据目录默认为二进制同级 ./data/
./vane --config /etc/vane     # 指定数据目录
VANE_SECRET=mysecret ./vane   # 自定义加密密钥（否则随机生成并写入 data/secret.key）
```

首次启动访问 `http://0.0.0.0:4455`，账号 `admin / admin`。

## Docker

```bash
docker run -d \
  --name vane \
  --restart unless-stopped \
  -p 4455:4455 \
  -v /etc/vane:/app/data \
  yourname/vane:latest
```

## 项目结构

```
src/
├── main.rs               # 入口，服务启动
├── assets.rs             # rust-embed 前端嵌入
├── config/
│   ├── mod.rs            # Config 共享状态
│   ├── types.rs          # 所有数据类型
│   ├── crypto.rs         # AES-256-GCM + PBKDF2
│   ├── db.rs             # SQLite (bundled) CRUD
│   └── ipfilter.rs       # IP 过滤逻辑
├── module/
│   ├── portforward.rs    # TCP/UDP 端口转发
│   ├── ddns.rs           # DDNS + Cloudflare API
│   ├── tls.rs            # ACME DNS-01 证书
│   └── webservice.rs     # 反向代理 + SNI TLS
└── api/
    ├── mod.rs            # axum 路由注册
    ├── auth.rs           # 登录/Session/速率限制
    ├── dashboard.rs
    ├── settings.rs       # 设置/备份/恢复
    ├── portforward.rs
    ├── ddns.rs
    ├── tls.rs
    ├── webservice.rs
    └── ipfilter.rs
web/                      # 前端源码（Vue 3，原版不动）
```

## 环境变量

| 变量 | 说明 | 默认值 |
|------|------|--------|
| `VANE_SECRET` | 配置加密主密钥 | 随机生成，存入 `data/secret.key` |
| `RUST_LOG` | 日志级别 | `vane=info` |

## License

MIT
