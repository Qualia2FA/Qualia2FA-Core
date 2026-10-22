<div align="center" style="align-items: center">

# Qualia2FA-Core

简体中文 | [English](README.en.md)

Qualia2FA 的核心库。

承载 Qualia2FA 的全部核心逻辑：验证码计算、URI 解析、加密保险库、设备配对与同步合并。

[![License](https://img.shields.io/github/license/Qualia2FA/Qualia2FA-Core?label=License)][License]
[![Releases](https://img.shields.io/github/downloads/Qualia2FA/Qualia2FA-Core/total?logo=github&label=Downloads)][Releases]
[![crates.io](https://img.shields.io/crates/d/qualia2fa-core?logo=crates.io&label=crates.io+Downloads)][crates.io]

[License]: LICENSE

[Releases]: https://github.com/Qualia2FA/Qualia2FA-Core/releases

[crates.io]: https://crates.io/crates/qualia2fa-core

</div>

---

**刻意不含任何界面或命令行入口**，也不做任何 I/O 与时钟读取——以便 Windows
、Android 等平台各自作为独立项目复用它。

## 状态

| 项         | 值                                        |
|------------|-------------------------------------------|
| Crate 名   | `qualia2fa-core`                          |
| 版本       | `0.4.1`                                   |
| 类型       | 纯 library crate                          |
| Edition    | 2024                                      |
| MSRV       | **1.89**                                  |
| 开发工具链 | `stable`（由 `rust-toolchain.toml` 固定） |
| 许可证     | `LGPL-3.0-or-later`                       |

支持以下功能：
- **2FA 验证码计算**：
  - HOTP（RFC 4226）
  - TOTP（RFC 6238）
  - mOTP
  - Yandex OTP
  - Steam Guard
- Base32（RFC 4648，宽容与严格两种模式）
- URI 解析与序列化（`otpauth://` 与 Aegis 的 `motp:`） 
- 加密保险库（本地存储格式）
- **树状分组（父关系、条目与子分组混合顺序）**
- **从 Aegis 的 JSON / HTML / TXT 导出导入（加密导出也能开），图标随条目落库**
- 恢复密钥与 `.q2fa` 容器（明文 / 加密保险库）
- 挑战-应答认证
- 设备配对
- 同步载荷与合并
- 传输层协议

## 用法

```toml
[dependencies]
qualia2fa-core = "0.2"
```

计算验证码：

```rust
use qualia2fa_core::otp::{self, Algorithm, Digits, OtpSecret};

let secret = OtpSecret::from_base32("JBSWY3DPEHPK3PXP")?;
// 当前时间由调用方传入——本库不读时钟
let code = otp::totp_code(&secret, 1_700_000_000, 30, Algorithm::Sha1, Digits::SIX)?;
assert_eq!(code.len(), 6);
```

导入一条 `otpauth://`：

```rust
use qualia2fa_core::uri;

let entry = uri::parse(
    "otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP&issuer=GitHub"
)?;
assert_eq!(entry.issuer.as_deref(), Some("GitHub"));
assert_eq!(entry.account, "alice");
```

校验用户输入，并容忍时钟漂移：

```rust
use qualia2fa_core::otp;

// 返回命中的偏移步数（0 = 当前步，-1 = 落后一步），而不是布尔值，
// 便于据此校准该条目的时钟偏差。比较是常量时间的。
let offset = otp::verify_with_drift(&secret, counter, 1, algorithm, digits, &user_input);
```

### 加密保险库

一条 `otpauth://` 配置存进保险库后就变成一条**逐条加密**的条目：每条有自己的
128-bit 随机 ID 与 XChaCha20-Poly1305 密文，文件里除了那些 ID 之外没有任何明文
语义——连「这是 TOTP 还是 HOTP」都看不出来。

```rust
use qualia2fa_core::vault::{self, Entry, VaultFile};

// 从扫码结果建条目。时间由调用方传入（本库不读时钟）。
let parsed = qualia2fa_core::uri::parse("otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP&issuer=GitHub")?;
let entry = vault::entry_from_parsed_uri(&parsed, now)?;

let mut file = VaultFile::create()?;              // 生成新的随机主密钥
let id = file.vault_mut().insert(entry)?;

let bytes = file.serialize()?;
vault::write_file_atomically(std::path::Path::new("vault.q2fa"), &bytes)?;
```

读回来需要**主密钥**——文件里不含它，只含一个由它派生的检查值（格式版本 2 起，
32 字节，只能回答「是不是这把密钥」，无法反推出主密钥）：

```rust
use qualia2fa_core::vault::{self, MasterKey};

let master: MasterKey = load_from_platform_keystore()?;   // 例如 Windows TPM
let file = vault::read_file(master, std::path::Path::new("vault.q2fa"))?;
for (id, entry) in file.vault().iter() {
    println!("{id} {}", entry.name);
}
```

几件需要知道的事：

- **主密钥丢失 = 数据永久无法解密。** 没有服务端、没有账号密码，也就没有找回途径。
  把主密钥存进平台硬件密钥库（Windows TPM、Android Keystore）已经可用，但那是
  上层（`qualia-dik` 与端侧应用）的事；本库只负责生成、派生与保管它。iOS 与 macOS 的
  Secure Enclave 仍在计划中。
- **文件可以被攻击者随意改写。** 任何一个字节被改动都会导致解密失败，而不是
  悄悄解出一份被篡改的数据。你自己实现存储层时也应当如此。
- **落盘请用 `write_file_atomically`。** 直接 `fs::write` 在断电时可能留下一个
  被截断的文件，而那意味着全部条目损坏。
- **删除会留下墓碑**（同样加密，只有 ID 与时间戳），这样「另一台设备还有这条」
  才可裁决。墓碑不设过期，每条 45 字节。
- 密文长度会泄露备注、账号名的**长短**。这是已知的、有意的取舍：掩盖它需要填充
  到定长块，代价是文件变大数倍。

### 解锁密码

主密钥通常放在平台密钥库里，读出它不需要用户做任何事。要在打开保险库之前先要求
一次认证，就把主密钥另存一份**只有口令能打开**的包裹，放在保险库旁边：

```rust
use qualia2fa_core::{KdfParams, SecretString, lock};

let password = SecretString::from("the unlock password".to_owned());

// 写入：Argon2id 派生 + XChaCha20-Poly1305，结果写进 master.key.pw。
let wrap = lock::wrap(&master_key, &password, &KdfParams::recommended())?;
std::fs::write("master.key.pw", &wrap)?;

// 读取：口令错就是口令错，不会解出一把「另一把密钥」。
let recovered = lock::unwrap(&wrap, &password)?;
```

包裹文件是定长 110 字节，自带 KDF 参数与随机盐，因此旧文件永远读得回来；参数来自
文件，属于不可信输入，**边界检查在 Argon2id 运行之前**完成。口令错、参数越界、版本
不认识是三种不同的错误，调用方据此区分「密码不对」和「文件坏了」。

与之配套的还有两个**不含任何秘密**的状态文件：`lock.marker`（锁已启用，以及两条
解锁路径是否可用）与 `lock.pending`（一次加锁操作写到一半）。它们的取值只用来决定
「该显示哪个界面」，真正的判据永远是包裹文件本身能不能打开——标记文件可以被随意
改写，而一个写着「已上锁」却没有包裹的设备，必须按打不开处理，而不是按没上锁处理。

平台认证那一条路径（`master.key.bio`）不在本库：它需要平台 API，而本库不碰平台。

## 兼容性

**保险库文件格式版本：4。** 本版本一律写版本 4，并且仍然能读版本 1–3 的文件
（可读版本只增不减）。版本 4 的分组记录是「名字 + 有序子节点列表」，条目可以带图标；
版本 1–3 的平铺分组被读成顶层下的命名分组。老版本应用读到版本 4 的文件会得到一个明确的
「版本不支持」错误；**唯一的例外**是版本 1 的解析器，它报的是文件尾部有多余内容（那 32
字节的主密钥检查值在它看来就是多余内容）。

**同步载荷版本：4。** 载荷只接受当前版本，因此 **0.2.x 与 0.3.0 之间的同步会失败**，
报的是版本错误而不是认证失败（版本号在明文头部，不需要密钥就能读到）。两端必须一起升级
——这是刻意的：条目明文里多了图标、分组明文换了形状、长度前缀从 u16 抬到 u32。

导入 Aegis 认证器的导出：

```rust
use qualia2fa_core::import::{self, ImportFormat};

// 字节进、报告出：本库不做 I/O，也不读时钟
let report = import::import(&bytes, ImportFormat::Json, now, None)?;
for entry in &report.entries {
    println!("{}", entry.entry.name);
}
// 与已有保险库比对：哪些是新的、哪些已经有了、哪些要人来定
let matches = import::apply::compare(&report, &vault);
```

导出成六种格式之一——两个 `.q2fa` 容器（`Vault` / `EncryptedVault`）与四种外部格式（`Text` / `Json` / `EncryptedJson` / `Html`）：

```rust
use qualia2fa_core::export::{self, ExportFormat};

// 同样是字节出、字节进：本库不做 I/O，写到哪里由调用方决定。
// 只有 EncryptedJson 与 EncryptedVault 需要口令。Vault 的主密钥是明文，
// 其余明文格式与保险库本身一样敏感。
let bytes = export::export(vault, ExportFormat::EncryptedJson, Some(b"password"))?;
```

## 设计约定

### 无 I/O、无时钟

不访问文件系统、网络、环境变量，不读系统时钟。**时间一律由调用方以 `u64`
Unix 秒传入。** 这不是洁癖：只有时间作为参数传入，RFC 6238 的测试向量才能被
确定性地验证。

随机数只用 `getrandom`（OS CSPRNG），不经任何用户态 PRNG。

### 绝不 panic

所有对外函数返回 `Result`，错误类型化。任何输入都不得导致 panic——包括恶意
二维码、剪贴板内容与手输链接。错误类型**绝不携带秘密材料**：不放进原始输入、
不放密钥字节、不放 OTP 码。

### 秘密材料的处理

库内所有秘密（OTP 种子、保险库主密钥、会话密钥）一律用 [`secrecy`] 的类型承载，
**不用裸 `Vec<u8>` / `String`**，使「这是秘密」在类型上可见：

| 用途                              | 类型                                 |
|-----------------------------------|--------------------------------------|
| 任意字节秘密（种子、密钥、nonce） | `SecretBytes`（= `SecretSlice<u8>`） |
| 文本秘密（口令、恢复短语）        | `SecretString`                       |
| 定长 / 其它秘密                   | `SecretBox`                          |
| 取用明文                          | `ExposeSecret` / `ExposeSecretMut`   |

以上类型全部由本库再导出，调用方**不需要**直接依赖 `secrecy`。

**该依赖已人工审计**（依赖必要性无法由 `cargo-deny` 代劳，故逐项核过）：

- 唯一必需依赖是 `zeroize ^1.6`，全树只有一个 `zeroize`。
- 可选依赖 `serde ^1` 本库不启用，不进依赖树。
- 上游 monorepo 活跃（未归档、近期有推送）；crate 本身自 2024-10 无新版本，属
  **成熟稳定而非废弃**，实现为纯逻辑封装（无 `unsafe`、无 FFI）。
- 本库**只在 `src/secret.rs` 一处接触它**，替换成本可控。

**与直觉不同的上游行为**：

- `secrecy` 的 `Debug` **连长度都不打印**，输出形如 `SecretBox<str>([REDACTED])`。
  需要长度时请自行 `expose_secret()`。
- `secrecy` 只为**原始整数**实现 `CloneableSecret`，**没有** `Vec`/`String`/`Box`
  的实现。因此本库的字节秘密统一用可克隆的 `SecretSlice<u8>`；**不要**改成
  `SecretBox<Vec<u8>>`，那会因不可克隆而无法通过编译。
- 这些保障**只覆盖**「明文被打印 / 忘记擦除 / 误克隆」，**不覆盖**编译器把明文
  复制到寄存器、栈副本或交换区。`forbid(unsafe_code)` 之下无法用 `mlock` 阻止
  换页，也**不防同进程内的恶意代码**。

### 平台原生调用不属于本库

需要 `unsafe` 的平台代码（如 Windows TPM/CNG 密钥库）隔离在独立 crate，
以保住本库的 `#![forbid(unsafe_code)]`。

[`secrecy`]: https://crates.io/crates/secrecy

## 接入你自己的项目

本库已发布到 crates.io：在 `Cargo.toml` 里写版本号即可，不需要 submodule，也不
需要指向上游目录的路径依赖。

```toml
[dependencies]
qualia2fa-core = "0.2"
```

> ⚠️ 若你用 **Gobley + uniffi** 做 Kotlin 绑定，注意 Gobley 当前强制
> `uniffi = "0.29.4"`。**不要把 uniffi 加进本库**——绑定应放在宿主侧或独立的
> FFI crate（例如 [`Qualia2FA-FFI`](https://github.com/Qualia2FA/Qualia2FA-FFI)），
> 以保持本库的依赖面干净、且不受绑定生成器的版本锁定牵连。

## 参与贡献

提交前请确保全绿：

```powershell
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
cargo doc --no-deps            # 文档链接与 intra-doc link 不得有警告
```

依赖审计与许可证策略（改动依赖后必跑）：

```powershell
cargo deny check
cargo audit
```

模糊测试（需要 nightly 与 cargo-fuzz，因为要用 `-Zsanitizer`）：

```powershell
rustup toolchain install nightly --component rust-src
cargo install cargo-fuzz --locked

cd fuzz
cargo +nightly fuzz list
cargo +nightly fuzz run uri_parse -- -max_total_time=300
cargo +nightly fuzz run vault_parse -- -max_total_time=300
```

`otpauth://` 解析器、Base32 解码与保险库文件解析都是**攻击者可控**的输入面，
改动它们时必须跑 fuzz。历史崩溃样本固化在 `fuzz/regressions/`，CI 每轮都会跑到。
详见 [`fuzz/README.md`](fuzz/README.md)。

### MSRV 策略

`rust-version = "1.89"` 是**最低支持声明**，不是开发工具链版本：

- **开发工具链**由 `rust-toolchain.toml` 固定为 `stable`，避免各人本机漂移。
- **MSRV 下限**由依赖栈决定（当前实际约束来自加密依赖栈；将来引入 KEM 后会更紧）。
- CI 有独立的 MSRV job，用 1.89 真机编译一遍——**声明的 MSRV 必须真的能编译**，
  否则这个字段就是谎言。

### 安全纪律

- **常量时间是编译产物的属性，不是 crate 的属性。** 上游源码看着是常量时间的，
  编译器仍可能生成分支（RustSec 上多起此类公告均属 codegen 失败）。因此
  **升级任何 crypto 依赖后必须重跑常量时间相关测试**。
- **依赖审计是安全控制，不是杂事。** RustSec 库 2026 年新增 334 条公告（2025 年
  为 172 条），本项目关注的上游问题几乎都在补丁/次版本中修复。`Cargo.lock` 入库，
  CI 跑 `cargo-deny`。
- **只发布 release 构建**：常量时间比较库的 `debug_assert` 使用依赖秘密的分支。
- **秘密材料永不进入**日志、错误消息、panic 信息或 `Debug` 输出。
- `deny.toml` 中有明确的禁用 crate 清单，每条都附了理由。

## 许可

本项目按 **GNU Lesser General Public License v3.0 or later**
（`LGPL-3.0-or-later`）授权。你可以依据自由软件基金会发布的 GNU 宽通用公共许可证
第 3 版，或（任选）任何更高版本的条款，再分发和/或修改本作品。

- [`COPYING.LESSER`](COPYING.LESSER)：LGPL-3.0 全文
- [`LICENSE`](LICENSE)：GPL-3.0 全文（LGPL-3.0 通过引用并入）

本作品出于希望其有用的目的分发，但不提供任何担保，甚至不提供适销性或特定用途
适用性的默示担保。详见许可证正文。
