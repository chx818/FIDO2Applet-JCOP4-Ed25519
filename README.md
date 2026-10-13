# FIDO2Applet for NXP JCOP 4 / JCOP 4.x (Hardware Ed25519 & ES256)

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![JavaCard](https://img.shields.io/badge/JavaCard-3.0.5-orange.svg)]()
[![Hardware](https://img.shields.io/badge/Target-NXP%20JCOP%204%20%2F%20JCOP%204.x-red.svg)]()
[![Hardware Crypto](https://img.shields.io/badge/Hardware%20Crypto-Ed25519%20(COSE%20--8)%20%2F%20ES256%20(COSE%20--7)-green.svg)]()
[![Build](https://img.shields.io/badge/Deterministic%20Build-Verified-brightgreen.svg)]()

[English](#english) | [中文说明](#中文说明)

---

<a name="english"></a>
## English Documentation

### 📖 1. Project Overview & Architectural Positioning

This repository provides a production-hardened, hardware-accelerated **FIDO2 CTAP2.1 & WebAuthn Java Card Applet** specifically optimized for **NXP JCOP 4 / JCOP 4.x** smart cards (such as the J3R family: J3R180, J3R200, J3R452, P71D600 series, and VivoKey FlexSecure).

This project bridges and elevates two pivotal open-source foundations:

1. **[BryanJacobs/FIDO2Applet](https://github.com/BryanJacobs/FIDO2Applet)**:
   - **Role**: High-level application implementation of the FIDO2 CTAP 2.0 / CTAP 2.1 and U2F specifications for Java Card Classic.
   - Covers resident keys (discoverable credentials), PIN Protocols 1 & 2, `credProtect`, `largeBlobs`, `credBlob`, `hmac-secret` (PRF extension), enterprise/basic attestation, and client credential management.
   - *Upstream Limitation*: Strictly limited to NIST P-256 (`ES256`, COSE algorithm `-7`). No support for Edwards-curve credentials (`Ed25519`).

2. **[suut/Curve25519-JavaCard](https://github.com/suut/Curve25519-JavaCard)**:
   - **Role**: On-card hardware cryptographic driver library (Package AID: `FF00025519`) specifically targeting the NXP JCOP 4.x hardware security coprocessor.
   - Provides native acceleration for Curve25519 operations via NXP's underlying silicon services, bypassing the lack of standard Java Card 3.1 `NamedParameterSpec` on Java Card 3.0.5 platforms.

#### The Problem Solved by This Project
Modern authentication standards, OpenSSH (`ed25519-sk`), and security-conscious users widely favor **Ed25519** for its speed, simplicity, and resistance to side-channel analysis. However, standard Java Card 3.0.5 environments lack native Edwards curve APIs, and previous Java Card FIDO2 applets only offered P-256.

**This project introduces native Ed25519 (COSE algorithm `-8`, PureEd25519, OKP format) to FIDO2Applet on NXP JCOP 4 / JCOP 4.x**, while preserving full backwards compatibility with hardware-accelerated **ES256 (COSE algorithm `-7`)**, U2F, and all CTAP 2.1 features. Furthermore, it addresses critical RAM constraints through deep **Clear-On-Reset (COR) memory optimizations**, enabling seamless coexistence with other applets (such as SmartPGP, PIV, and OTP) on the same JCOP 4 card.

---

### 🌟 2. Key Capabilities & Algorithm Support

| Feature / Algorithm | Specification & Standards | Technical Details |
| :--- | :--- | :--- |
| **Native Ed25519** | COSE Algorithm `-8`, RFC 8032 | PureEd25519 (`authenticatorData \|\| clientDataHash`), OKP public key (`crv: 6`), 64-byte raw signature (`r \|\| s`) |
| **Native ES256** | COSE Algorithm `-7`, FIPS 186-4 | NIST P-256 (secp256r1), ECDSA-SHA256, EC2 public key format, hardware coprocessor accelerated |
| **Algorithm Negotiation** | CTAP 2.1 §5.1 | Negotiates RP preference; gracefully falls back to ES256 if client does not request Ed25519 |
| **Self-Attestation** | WebAuthn / CTAP 2.1 | Automatically matches credential algorithm (produces 64-byte Ed25519 self-attestation signature for Ed25519 credentials) |
| **Basic Attestation** | X.509 Certificate Chain | Dedicated P-256 device attestation key and certificate chain; capable of issuing device attestation for Ed25519 credentials |
| **Unified Credential ID** | 112-byte Encrypted Token | `IV (16B) \|\| AES-CBC Ciphertext (80B) \|\| HMAC-SHA256 (16B)`. Algorithm encoded in authenticated flags (`0x40`). Does not inflate ES256 ID size |
| **PIN Protocols** | PIN Protocol 1 & Protocol 2 | Retains standard P-256 ECDH, AES-256-CBC, and HMAC-SHA256 session encryption |
| **CTAP1 / U2F Fallback** | FIDO U2F v1.2 | Full U2F register and authenticate support for P-256 credentials; Ed25519 credentials cleanly rejected per U2F spec |
| **Advanced Extensions** | CTAP 2.1 Specification | `credProtect` (levels 1, 2, 3), `credBlob`, `largeBlobKey`, `authenticatorLargeBlobs` (1024B default), `hmac-secret` (PRF), `minPinLength`, `alwaysUv` |

---

### 🧠 3. Memory Architecture & JCOP 4 Multi-Applet Coexistence

Smart cards powered by **NXP JCOP 4 / JCOP 4.x** divide volatile memory into two distinct pools:
- **Clear-On-Reset (COR)**: Preserved across applet selections and deselections, wiped only upon physical power reset or card ATR.
- **Clear-On-Deselect (COD)**: Wiped automatically whenever the applet is deselected or another applet is selected.

#### The JCOP 4 Memory Bottleneck
When co-hosting multiple applets on a single JCOP 4 card (e.g. **SmartPGP**, **PIV**, **VivoKey OTP**, **Satochip**, and **FIDO2**), **Clear-On-Reset (COR) is the most critical bottleneck**. If FIDO2 hoards COR RAM, subsequent applet installations or runtime crypto operations in SmartPGP / PIV will throw `6A84` (Not enough memory) or `6F00`.

#### Memory Optimizations in This Fork
1. **Explicit COR State Reduced from 16 Bytes to 1 Byte**:
   - Upstream FIDO2Applet held a 16-byte COR state array across card resets.
   - This fork migrates all command state, indexing, chunking, and session context to **16 bytes of COD**.
   - **Only 1 byte of COR** is retained: the physical power-on PIN failure counter, ensuring brute-force protection cannot be bypassed by card resets, while releasing virtually all COR RAM.
2. **Session Reconstruction on DESELECT**:
   - Ephemeral P-256 PIN keys prioritize COD. PIN sessions are cleanly reconstructed upon explicit applet selection before handling large requests.
3. **On-Demand Scratch Buffer Borrowing**:
   - Instead of allocating a permanent dedicated 128-byte transient signature array, the Ed25519 signing engine dynamically borrows 64-byte or 128-byte work buffers from `BufferManager` and zeroes them immediately upon operation completion.
4. **Persistent Object for Ed25519 Public Key**:
   - The Ed25519 private key strictly resides in COD (zeroized on deselect).
   - The public key utilizes persistent storage (holding only non-secret public coordinates), avoiding permanent RAM allocation while being explicitly zeroized before restoring new seeds.
5. **Transparent Memory Accounting**:
   - Adding native Ed25519 cryptographic state introduces a modest net footprint compared to ES256-only (+187 bytes net COR after full initialization), but saves 160 bytes compared to earlier Ed25519 candidate implementations.
   - In lab benchmarks on JCOP 4 cards with SmartPGP pre-installed, this fork operates stably with ample headroom.

---

### 🛡️ 4. Security Hardening & Resilience

This fork includes comprehensive audit and defensive improvements based on static analysis, fuzzing campaigns, and hardware validation:

1. **Atomic Resident Credential Replacement**:
   - *Upstream Issue*: Upstream committed resident credential slot updates *before* computing the final attestation signature. If key generation or attestation failed, an existing resident key could be overwritten and destroyed.
   - *Fix*: Candidate credentials are fully generated, signed, and formatted in an uncommitted staging state. The resident credential array pointers and counters are only committed in a final, short atomic transaction.
2. **Transaction Isolation with Driver Library**:
   - The low-level `Curve25519.cap` wrapper manages internal hardware transactions. The adapter enforces `JCSystem.getTransactionDepth() == 0` before entering native routines, preventing nested transaction aborts.
3. **Strict Private Key Material Zeroization**:
   - Transient Ed25519 seeds, scalars, and scratch buffers are wiped immediately after signing.
   - A unified APDU exit handler ensures that both ECDSA and Ed25519 private key objects are scrubbed even if an unexpected exception occurs during request execution.
4. **Constant-Time / Fixed-Length Verification**:
   - PIN token MACs, credential HMAC verification, `saltAuth`, and PIN wrapper validations use fixed-length XOR/OR accumulators, eliminating timing side-channels from early loop exits.
5. **Chaining Error Recovery & Delayed Status**:
   - In long APDU chains (e.g. certificate injection), if an error occurs mid-stream, a 1-byte COD flag ensures subsequent inbound chunks are cleanly drained before reporting the error, preventing client desynchronization.
6. **Native Exception Allocator Recovery**:
   - Fixed an edge case where consecutive native driver errors could bypass the standard error path and leave `BufferManager` allocations unfreed. Allocations and iteration states are now systematically reset upon abnormal exit.

---

### 🔏 5. Attestation & Customization Lifecycle

1. **Initial Provisioning Window**:
   - By default, this applet allows injecting a custom batch/device attestation private key and X.509 certificate chain before any credentials have been created.
2. **Permanent Attestation Lock**:
   - As soon as the first credential is created, attestation injection is permanently locked.
   - Once successfully injected, custom attestation identities survive CTAP card resets.
3. **Factory Locking Option**:
   - For enterprise or high-security factory deployments where attestation must not be altered, installing with parameter `A100F4` permanently locks self-attestation mode and disables injection immediately.
4. **Dual Algorithm Attestation**:
   - Supports both **PureEd25519 self-attestation** (for Ed25519 credentials) and **P-256 basic attestation** (signing Ed25519 `authenticatorData || clientDataHash` with an injected device ECDSA certificate).

---

### 🚀 6. Installation & Flashing Guide

#### Prerequisites
- An **NXP JCOP 4 / JCOP 4.x** smart card (e.g. J3R180, J3R200, J3R452, P71D600 series, or VivoKey FlexSecure).
- A compatible PC/SC smart card reader (contact or NFC).
- [GlobalPlatformPro](https://github.com/martinpaljak/GlobalPlatformPro) (`gp.exe`).

#### Installation Steps

1. **Step 1: Install the Hardware Curve25519 Driver Library**
   The driver package must be installed first (Package AID: `FF00025519`):
   ```powershell
   gp --install lib/Curve25519.cap
   ```

2. **Step 2: Install FIDO2Applet**
   Install the release CAP (Package AID: `A000000647`, Applet AID: `A0000006472F0001`):
   ```powershell
   gp --install dist/FIDO2-Ed25519.cap
   ```

3. **Optional: Android NFC / Google Play Services (`CardReset` Privilege)**
   If you plan to use the card over NFC with Android Google Play Services (which requires card reset privileges for default selection), install with `--priv 4`:
   ```powershell
   gp --install dist/FIDO2-Ed25519.cap --priv 4
   ```

4. **Verification**
   Query the installed applets to confirm both packages are active:
   ```powershell
   gp -l
   ```
   You should see:
   - Package: `FF00025519` (Curve25519 native library)
   - Package: `A000000647` / Applet: `A0000006472F0001` (FIDO2Applet)

---

### 🔨 7. Reproducible Build & Release Verification

This repository adheres to deterministic, reproducible build standards. The prebuilt CAP in `dist/` is bit-for-bit identical across multiple clean environments.

#### Verified Release Artifacts
- **CAP File**: `dist/FIDO2-Ed25519.cap`
- **SHA-256**: `b09f8213896ee6fc7866be02cdff748815a0b49636cb96f905a40d06b5df9e1f`

#### Building from Source
Requirements: JDK 11, Oracle Java Card 3.0.5 SDK, Oracle 3.1 Converter.
```powershell
python tools/build_cap.py --jdk <path_to_jdk11> --sdk305 <path_to_jc305> --sdk310 <path_to_jc310>
```

#### Verifying Release Integrity
To verify the provenance, source files, and checksums of the release CAP:
```powershell
python tools/verify_release.py
```

---

### 💻 8. Client & Platform Compatibility

| Client / Use Case | Protocol & Algorithm | Compatibility Notes |
| :--- | :--- | :--- |
| **OpenSSH** (`ssh-keygen`) | `ed25519-sk` & `ecdsa-sk` | Fully supported, including resident keys (`-O resident`) |
| **WebAuthn / Passkeys** | Ed25519 & ES256 | Chrome, Microsoft Edge, Firefox, Safari (via WebAuthn) |
| **Linux PAM** (`pam-u2f`) | FIDO2 / U2F | Supported for local console and sudo authentication |
| **LUKS Disk Encryption** | `systemd-cryptenroll --fido2-device=auto` | Supported via `hmac-secret` extension |
| **Python Client** | `python-fido2` | Full protocol compliance and test suite coverage |
| **Bridges & Utilities** | FIDOk, libfido2, CTAP-bridge | Supported over PC/SC and USB-HID bridge wrappers |

> **Note on Windows PC/SC Access**: Under Windows 10/11, native WebAuthn APIs manage the FIDO AID directly. Running direct raw APDUs against the FIDO AID via standard user processes may be restricted by the OS; run as Administrator or access through standard WebAuthn / OpenSSH APIs.

---

### 📄 9. Upstream Credits & License

- **Bryan Jacobs** ([BryanJacobs/FIDO2Applet](https://github.com/BryanJacobs/FIDO2Applet)): Original FIDO2 / CTAP2 Java Card implementation, licensed under **Apache-2.0**.
- **suut** ([suut/Curve25519-JavaCard](https://github.com/suut/Curve25519-JavaCard)): NXP JCOP hardware Curve25519 driver library.
- This project is licensed under the **Apache License 2.0**. See the [LICENSE](LICENSE) file for complete details.

---

<a name="中文说明"></a>
## 中文说明

### 📖 1. 项目背景与架构定位

本项目提供了一个经过深度安全审计与生产加固的 **FIDO2 CTAP2.1 与 WebAuthn Java Card 智能卡应用**，专门针对 **NXP JCOP 4 / JCOP 4.x** 智能卡平台（如 J3R 家族系列：J3R180、J3R200、J3R452、P71D600 系列以及 VivoKey FlexSecure）进行了深度硬件适配与内存架构优化。

本项目融合并扩展了两个关键的开源基石：

1. **[BryanJacobs/FIDO2Applet](https://github.com/BryanJacobs/FIDO2Applet)**：
   - **定位**：功能完备的 Java Card Classic FIDO2 CTAP 2.0 / CTAP 2.1 和 U2F 应用协议实现。
   - 支持驻留密钥（Discoverable Credentials）、PIN 协议 1 与 2、`credProtect` 凭据保护、`largeBlobs`、`credBlob`、`hmac-secret`（WebAuthn PRF 扩展）、证书证明链注入和客户端凭据管理。
   - *上游局限*：仅支持 NIST P-256（`ES256`，COSE 算法 `-7`），完全不支持 Edwards 椭圆曲线凭据（`Ed25519`）。

2. **[suut/Curve25519-JavaCard](https://github.com/suut/Curve25519-JavaCard)**：
   - **定位**：卡上硬件密码驱动库（Package AID: `FF00025519`），针对 NXP JCOP 4.x 硬件安全协处理器编写。
   - 绕过 Java Card 3.0.5 规范缺乏标准 25519 接口的限制，直接利用 NXP 芯片原生密码引擎在硬件中执行 Curve25519 运算。

#### 本项目解决的核心痛点
在现代身份认证与 OpenSSH（`ed25519-sk`）场景中，**Ed25519** 因其出色的签名速度、简洁的设计和强大的侧信道抗性受到极高青睐。但在 Java Card 3.0.5 体系下，标准规范仅支持 Weierstrass 曲线。

**本项目在 NXP JCOP 4 / JCOP 4.x 平台上实现了原生硬件加速的 Ed25519（COSE 算法 `-8`，PureEd25519，OKP 格式）**，同时完整保留了原有的硬件加速 **ES256（COSE 算法 `-7`）**、U2F 以及全部 CTAP 2.1 规范特性。更重要的是，针对 JCOP 4 智能卡多应用共存的内存瓶颈，本项目实施了深度的 **Clear-On-Reset (COR) 内存优化**，确保能与 **SmartPGP**、**PIV**、**VivoKey OTP** 等应用在一张卡上稳定共存！

---

### 🌟 2. 核心功能与算法支持

| 功能 / 算法 | 遵循规范与标准 | 技术细节与实现特性 |
| :--- | :--- | :--- |
| **原生 Ed25519** | COSE 算法 `-8`，RFC 8032 | PureEd25519 签名（`authenticatorData \|\| clientDataHash`），OKP 公钥格式（`crv: 6`），64 字节标准 `r \|\| s` 签名 |
| **原生 ES256** | COSE 算法 `-7`，FIPS 186-4 | NIST P-256 (secp256r1)，ECDSA-SHA256，EC2 公钥格式，芯片硬件协处理器加速 |
| **算法自适应协商** | CTAP 2.1 §5.1 | 严格按客户端 RP 偏好协商首个匹配算法；客户端未声明 Ed25519 时自动降级为 ES256 |
| **自证明 (Self-Attestation)** | WebAuthn / CTAP 2.1 | 自证明算法动态跟随凭据类型（Ed25519 凭据输出 64 字节 Ed25519 自证明签名） |
| **基础设备证明 (Basic Attestation)** | X.509 证书链 | 独立的 P-256 设备证明私钥与 X.509 证书链，支持为 Ed25519 凭据签发设备身份证明 |
| **统一 112 字节凭据 ID** | 统一加密封装格式 | `IV (16B) \|\| AES-CBC 载荷 (80B) \|\| 截断 HMAC-SHA256 (16B)`。算法标志包含在经 HMAC 认证的载荷中（`0x40` 位，`0x80` 为驻留标志），不膨胀原有 ES256 凭据长度 |
| **PIN 安全协议** | PIN Protocol 1 & Protocol 2 | 保持标准的 P-256 ECDH 密钥交换、AES-256-CBC 和 HMAC-SHA256 会话加密 |
| **CTAP1 / U2F 兼容** | FIDO U2F v1.2 | 完整保留 P-256 的 U2F 注册与认证逻辑；规范要求下 Ed25519 凭据明确拒绝进入 U2F |
| **完备扩展支持** | CTAP 2.1 规范扩展 | 支持 `credProtect`（保护级别 1/2/3）、`credBlob`、`largeBlobKey`、`authenticatorLargeBlobs`（默认 1024B）、`hmac-secret`（双盐/PRF）、`minPinLength`、`alwaysUv` |

---

### 🧠 3. 内存架构与 JCOP 4 多应用共存优化

**NXP JCOP 4 / JCOP 4.x** 智能卡系统的 RAM 划分为两个独立池：
- **Clear-On-Reset (COR)**：在应用选择（Select）和取消选择（Deselect）之间保持持久，仅在物理断电复位或产生 ATR 时被清空。
- **Clear-On-Deselect (COD)**：在应用被取消选择或切换到其他应用时自动清空。

#### JCOP 4 的内存痛点
在单张 JCOP 4 卡片上部署多个安全应用（例如同时安装 **SmartPGP**、**PIV**、**VivoKey OTP**、**Satochip** 和 **FIDO2**）时，**COR 是全卡最稀缺的全局资源**。若 FIDO2 占用过多 COR，其他应用在运行密钥生成或大密钥运算时就会触发 `6A84`（内存不足）崩溃。

#### 本分支的内存优化措施
1. **显式 COR 状态从 16 字节压缩至 1 字节**：
   - 上游实现将整个 16 字节的运行状态数组常驻在 COR 中。
   - 本分支将选项、索引、分包收发等运行状态全部迁入 **16 字节 COD**。
   - **仅保留 1 字节 COR** 用于记录上电期间的 PIN 错误重试计数，确保防暴力破解计数跨应用切换不丢失，同时释放绝大部分 COR 空间。
2. **取消选择时重建会话 (COD 优先)**：
   - PIN 临时 P-256 私钥和会话令牌优先分配在 COD 中。在新选择应用时按需重建会话，既保证安全性，又避免跨选择锁死 COR。
3. **签名暂存区动态按需借用**：
   - 上游及早期候选独占一个常驻 128 字节 COD 数组作为 Ed 签名暂存区。
   - 本版本改为从现有的 `BufferManager` 按需动态借用 64 字节或 128 字节工作区，完成签名后立即清零归还，避免常驻双份内存开销。
4. **Ed25519 公钥采用持久对象**：
   - Ed 私钥严格保存在 COD 临时内存中（断电或取消选择即清空）。
   - Ed 公钥改为持久对象（仅存储完全公开的公钥坐标），避免额外消耗珍贵的 RAM，并在载入新 seed 前显式清零。
5. **真实客观的内存成本说明**：
   - 在 JCOP 4 实体卡实测中，支持 Ed25519 相比仅支持 ES256 的纯上游版本存在合理的净开销（同卡完整初始化后净多占约 187 字节 COR），但比早期 Ed 候选版本减少了 160 字节 COR。
   - 经过实测，该内存占用配置能够与 SmartPGP（启用 RSA 4096 / Curve25519）完美和谐共存。

---

### 🛡️ 4. 安全加固与可靠性改进

本分支通过代码审计、故障注入模拟和硬件实测，修复并加固了以下关键安全机制：

1. **驻留凭据原子化更新与掉电保护**：
   - *上游隐患*：上游在计算最终证明签名之前就先写入并更新了驻留凭据槽位。一旦底层硬件生成密钥或证明签名失败，原有同 RP 的旧凭据已被覆盖破坏。
   - *加固方案*：构造完整的候选凭据、完成密码运算与验证后，在独立的简短事务中原子化更新槽位与索引。若中间失败，旧凭据完好保留，不产生无效幽灵记录。
2. **底层驱动事务隔离**：
   - 底层 `Curve25519.cap` 原生包装具有独立事务机制。适配层在调用前强制校验 `JCSystem.getTransactionDepth() == 0`，杜绝嵌套事务异常导致调用者事务被破坏。
3. **私钥敏感材料全路径清零**：
   - Ed25519 私钥 seed 和 scalar 签名完成后立即擦除。
   - 统一 APDU 出口增加防御性异常捕获清理，确保无论是正常响应还是抛出异常，ECDSA 和 Ed25519 临时私钥均被彻底擦除。
4. **恒定长度认证比较**：
   - PIN token MAC、凭据 HMAC、`saltAuth` 和 PIN 包装校验采用固定公开长度的累积异或（XOR/OR）比较，消除因数据内容导致的控制流提前退出风险。
5. **分包传输错误恢复与延迟响应**：
   - 客户端在发送超长 APDU 链（如证书链导入）中途发生协议错误时，新增 1 字节 COD 延迟错误标志，丢弃后续残留分片并在链末返回正确状态字，防止客户端与卡片会话脱节。
6. **连续原生异常内存恢复**：
   - 修复了连续发生底层原生异常时因跳过常规清理而导致 `BufferManager` 工作区计数未复位的缺陷。现在即使连续遭遇 40 次底层异常，后续命令仍能自动恢复使用。

---

### 🔏 5. 证明证书与生命周期管理

1. **初始证明身份注入窗口**：
   - 本分支默认策略允许在尚未生成任何凭据的新卡上，直接注入自定义的设备/批次证明私钥与 X.509 证书链（无需繁琐的安装参数）。
2. **永久锁定机制**：
   - 一旦卡片创建了第一个用户凭据，证明证书注入通道即被**永久锁定**，严防未经授权的篡改。
   - 成功注入的证明身份在执行 CTAP 卡片重置（Reset）后仍然保留并锁定。
3. **出厂预锁能力**：
   - 针对需要出厂即锁死自证明模式的生产流程，安装时传入参数 `A100F4` 即可永久禁用注入功能。
4. **双算法证书支持**：
   - 既支持纯粹的 **PureEd25519 自证明**，也支持通过注入的 P-256 根证书链为 Ed25519 凭据出具基础证明（Basic Attestation）。

---

### 🚀 6. 安装与烧录指南

#### 准备工作
- 一张 **NXP JCOP 4 / JCOP 4.x** 智能卡（如 J3R180、J3R200、J3R452、P71D600 系列或 VivoKey FlexSecure）。
- 支持 PC/SC 的接触式或 NFC 读卡器。
- [GlobalPlatformPro](https://github.com/martinpaljak/GlobalPlatformPro)（`gp.exe`）。

#### 烧录步骤

1. **第一步：安装 Curve25519 硬件驱动库**
   驱动包必须首先安装（Package AID: `FF00025519`）：
   ```powershell
   gp --install lib/Curve25519.cap
   ```

2. **第二步：安装 FIDO2Applet 应用**
   安装发行的 CAP 文件（Package AID: `A000000647`，Applet AID: `A0000006472F0001`）：
   ```powershell
   gp --install dist/FIDO2-Ed25519.cap
   ```

3. **可选步骤：Android NFC / Google Play 服务的 `CardReset` 权限**
   若希望在 Android 手机上通过 NFC 使用 Google Play Services 的 FIDO2 功能（其默认选择流程需要卡片重置权限），可携带 `--priv 4` 安装：
   ```powershell
   gp --install dist/FIDO2-Ed25519.cap --priv 4
   ```

4. **验证安装状态**
   查询已安装应用列表：
   ```powershell
   gp -l
   ```
   输出中应包含：
   - Package: `FF00025519`（Curve25519 底层驱动）
   - Package: `A000000647` / Applet: `A0000006472F0001`（FIDO2 主应用）

---

### 🔨 7. 可复现构建与校验

本项目遵照确定性构建规范，`dist/` 目录中的 CAP 文件在不同干净构建环境中可逐字节完全复现。

#### 已验证发行产物哈希
- **文件路径**：`dist/FIDO2-Ed25519.cap`
- **SHA-256 哈希值**：`b09f8213896ee6fc7866be02cdff748815a0b49636cb96f905a40d06b5df9e1f`

#### 从源码构建
环境要求：JDK 11，Oracle Java Card 3.0.5 SDK，Oracle 3.1 Converter。
```powershell
python tools/build_cap.py --jdk <path_to_jdk11> --sdk305 <path_to_jc305> --sdk310 <path_to_jc310>
```

#### 校验发行文件完整性
无需连接实体卡，执行以下脚本即可全自动比对源码、依赖和 CAP 哈希：
```powershell
python tools/verify_release.py
```

---

### 💻 8. 客户端与生态兼容性

| 客户端 / 应用场景 | 协议与算法 | 兼容性说明 |
| :--- | :--- | :--- |
| **OpenSSH** (`ssh-keygen`) | `ed25519-sk` 与 `ecdsa-sk` | 完美支持生成与登录认证，支持驻留密钥（`-O resident`） |
| **现代浏览器 / Passkeys** | Ed25519 与 ES256 | Chrome、Microsoft Edge、Firefox、Safari（原生 WebAuthn 支持） |
| **Linux PAM** (`pam-u2f`) | FIDO2 / U2F | 支持本地终端登录、sudo 认证等安全场景 |
| **LUKS 磁盘加密** | `systemd-cryptenroll --fido2-device=auto` | 支持通过 `hmac-secret` 扩展自动解密磁盘分区 |
| **Python 客户端** | `python-fido2` | 协议完整兼容，支持自动化测试与脚本管理 |
| **中继工具与桥接器** | FIDOk、libfido2、CTAP-bridge | 支持通过 PC/SC 与 USB-HID 桥接软件协同工作 |

> **Windows 下 PC/SC 访问说明**：在 Windows 10/11 系统中，操作系统的 WebAuthn 服务会独占对 FIDO AID 的底层管理。普通用户进程若直接通过原始 APDU 与 FIDO AID 通信可能会被系统拦截，建议通过标准 WebAuthn API / OpenSSH 工具或以管理员身份运行测试脚本。

---

### 📄 9. 致谢与开源协议

- **Bryan Jacobs**（[BryanJacobs/FIDO2Applet](https://github.com/BryanJacobs/FIDO2Applet)）：原始 FIDO2 / CTAP2 Java Card 应用开源作者，基于 **Apache-2.0** 协议授权。
- **suut**（[suut/Curve25519-JavaCard](https://github.com/suut/Curve25519-JavaCard)）：NXP JCOP 硬件 Curve25519 驱动库开源作者。
- 本项目遵循 **Apache License 2.0** 开源协议，完整协议内容请参阅 [LICENSE](LICENSE) 文件。
