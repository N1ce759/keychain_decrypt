# 🔐 keychain_decrypt ｜ English version: [README_EN.md](./README_EN.md)

纯 Rust 编写的 macOS `login.keychain-db` 离线解密工具。

无需调用 Apple Security.framework，直接从钥匙串数据库文件中提取 **Chrome Safe Storage** 密码——适用于跨平台取证、备份恢复和安全研究。

## ✨ 特性

- **纯 Rust** — 无 C 依赖，无需 macOS SDK
- **离线解密** — 直接操作 `.keychain-db` 二进制文件
- **完整密钥层级** — PBKDF2 → DB Key → KeyBlob → SSGP 全链路实现
- **极小体积** — Release 构建启用 LTO、strip 及 `opt-level = "z"`

## 🔑 解密原理

```
  用户密码
     │
     ▼
  ┌──────────────────────┐
  │  PBKDF2-HMAC-SHA1    │  1000 次迭代
  │  + DBBlob 中的 salt  │
  └──────────┬───────────┘
             │
             ▼
        主密钥 (24 字节)
             │
             ▼
  ┌──────────────────────┐
  │  3DES-CBC 解密       │  IV 来自 DBBlob
  │  DBBlob 密文         │
  └──────────┬───────────┘
             │
             ▼
        DB Key (24 字节)
             │
             ▼
  ┌──────────────────────┐
  │  两轮 3DES-CBC 解密  │  magicCmsIV → 反转 → 记录 IV
  │  KeyBlob 解密        │
  └──────────┬───────────┘
             │
             ▼
      记录密钥 (24 字节)
             │
             ▼
  ┌──────────────────────┐
  │  3DES-CBC 解密       │  IV 来自 SSGP 头部
  │  SSGP 密文           │
  └──────────┬───────────┘
             │
             ▼
       明文密码
```

## 📦 环境要求

- Rust 1.56+（edition 2021）
- 可访问的 `login.keychain-db` 文件（macOS 上需要完全磁盘访问权限）
- USER的登录密码

## 🚀 使用方法

### 编译

```bash
# 调试构建
cargo build

# 优化后的 Release 构建
cargo build --release
```

### 运行

```bash
keychain_decrypt --keychain <钥匙串路径> --password <钥匙串密码>
```

**示例：**

```bash
./target/release/keychain_decrypt \
  --keychain ~/Library/Keychains/login.keychain-db \
  --password "my_login_password"
```

**输出：**

```
[*] Read keychain file: 273624 bytes
[*] Keychain signature: "kych", schema at 0x38
[*] Found 5 tables
[*] Built table map (5 entries)
[*] DBBlob: magic=0xFADE0711, salt=..., iv=...
[*] Derived master key (PBKDF2): ...
[*] Decrypted DB key: ...
[*] Found 3 symmetric key records
[*] Decrypted 3 key blobs
[*] Found 1 'Chrome Safe Storage' entries
[+] Chrome Safe Storage password (plaintext):
    <解密后的密码>
[+] Hex: ...
[+] Length: 16 bytes
```

## 📁 项目结构

```
keychain_decrypt/
├── Cargo.toml          # 依赖配置 & Release 优化选项
└── src/
    ├── main.rs         # CLI 入口 & 解密流程编排
    ├── crypto.rs       # PBKDF2、3DES-CBC、密钥层级解密
    ├── parser.rs       # 二进制格式解析（头部、表、Blob）
    └── error.rs        # 统一错误类型
```

| 模块       | 职责                                                                 |
|------------|----------------------------------------------------------------------|
| `main`     | 命令行参数解析、高层解密流程、输出格式化                                |
| `crypto`   | `derive_master_key`、`decrypt_db_key`、`decrypt_key_blob`、`decrypt_ssgp` |
| `parser`   | 大端序读取、头部 / Schema / 表 / DBBlob / SSGP 解析                   |
| `error`    | `KeychainError` 枚举，实现 `Display` 和 `From<io::Error>`            |

## 🔧 依赖项

| Crate    | 版本  | 用途                            |
|----------|-------|---------------------------------|
| `des`    | 0.8   | Triple DES（3DES / DES-EDE3）    |
| `cbc`    | 0.1   | CBC 分组密码模式                 |
| `pbkdf2` | 0.12  | PBKDF2 密钥派生                  |
| `hmac`   | 0.12  | 用于 PBKDF2 的 HMAC              |
| `sha1`   | 0.10  | PBKDF2-HMAC-SHA1 所需的 SHA-1    |
| `cipher` | 0.4   | 分组密码 Trait                    |
| `hex`    | 0.4   | 十六进制编码（调试输出）          |

## ⚠️ 免责声明

本工具仅用于**合法的安全研究、数字取证及个人备份恢复**。未经授权访问他人钥匙串数据可能违反相关法律法规，请合法合规使用。

## 📄 许可证

MIT
