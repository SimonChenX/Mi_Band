# Mi Band 6 逆向 / 自研固件 —— 交接包

给接手做**反编译 + 自研固件**的团队。目标：**为小米手环 6（NFC 版）刷入自己的固件**。

---

## 0. 目标与现状（先读这段）

| 项 | 内容 |
|---|---|
| 设备 | 小米手环 6 NFC（Chinese NFC） |
| 型号串 | `hmpace.motion.v6nfc` |
| 固件版本 | `V1.0.6.10`（PANGU 平台） |
| 平台 | ARM Cortex-M，**Thumb** 指令集 |
| 当前进度 | 已能**直连手环并认证**（ECDH B-163）；已逆出固件镜像结构、马达/ECF 命令框架、部分协议 |
| 目标进度 | 尚未完成：**固件签名/安全启动是否可绕过、如何刷入** ← 需要团队重点评估 |

> ⚠️ 关键未知：手环的 **DFU/固件校验（签名、CRC、可能的安全启动）** 尚未核实。刷自研固件是否可行，取决于这一层——请优先评估。

---

## 1. 目录结构

```
zip/
├── README.md                       ← 本文件
├── AUTH_KEY.txt                    ← 本设备的 Auth Key（连接手环必需）
├── firmware/                       ← 固件原始文件（未解密，可直接分析）
│   ├── PANGU_1.0.6.10.fw   2.2 MB   主固件
│   ├── PANGU_2.ft          7.2 MB   字体/表
│   └── PANGU_59.res        2.7 MB   资源
├── original/
│   └── 1.0.6.10_PANGU_202110211347.zip   官方下载原包（未改动）
├── docs/
│   ├── FIRMWARE.md                 ← 固件逆向笔记（**最重要，先看**）
│   └── PROTOCOL.md                 ← BLE / Huami 2021 协议笔记
└── tools/
    └── fw_analyze.py               ← 固件分析工具（字符串/引用/反汇编）
```

> 🔒 `AUTH_KEY.txt` 是**本设备专用密钥**，只在这个交接包内使用，**禁止提交公开仓库 / 公开转发**。

固件来源（可复现）：
```
https://schakal.ru/fw/Mi_Band_6_Chinese_NFC_PANGU_211/1.0.6.10_PANGU_202110211347.zip
版本库：https://schakal.ru/fw/all_versions.json   （key 211 = Mi Band 6 Chinese NFC）
```

---

## 2. 分析固件 —— 快速上手

### 2.1 镜像结构（必看）
- `.fw` 文件开头是 **`0x400` 字节容器头**，之后才是镜像；
- **`地址 = 文件偏移 − 0x400`**；
- 入口向量表在文件 `0x400`（SP=`0x20034578`，Reset=`0x32d`）；
- **未加密**：镜像里有大量日志字符串与源码路径（如 `projects\huami_project\app\ECDH\ecdh.c`），`strings` 直接可读。

### 2.2 工具
```sh
python3 tools/fw_analyze.py firmware/PANGU_1.0.6.10.fw info
python3 tools/fw_analyze.py firmware/PANGU_1.0.6.10.fw str motor        # 搜字符串
python3 tools/fw_analyze.py firmware/PANGU_1.0.6.10.fw refs 0x16feba    # 找引用
python3 tools/fw_analyze.py firmware/PANGU_1.0.6.10.fw func 0xcbf8      # 反汇编函数
```
依赖：`pip install capstone`

> 坑（已踩）：**整镜像线性反汇编会因内联数据而失步**。找调用者要「逐个 2 字节位置用 capstone 解码」，否则找不到。`docs/FIRMWARE.md` 里有代码片段。

### 2.3 快速 `strings` 定位
```sh
strings -n 5 firmware/PANGU_1.0.6.10.fw | grep -iE "motor|find|ecf|auth|dfu|ota|secure|sign"
```

---

## 3. 已逆出的关键信息（详见 docs/FIRMWARE.md）

### 3.1 马达 / 震动（ECF 命令框架）
```
ECF 分发器            0xc8e0    (switch payload[0])
  命令 0x20 = ecf_set_custom_motor
      payload[0]=0x20, payload[1]=槽位 0..9,
      payload[2]=位域 bits0-5=type | bit6=flag | bit7=custom,
      payload[3..]=波形：每步 2×uint16(LE)=(震动ms,停顿ms)，总长≤12000ms
  命令 0x28 = ecf_set_ad_reminder_data
马达层：0x13cf8/0x13d34（内置波形）  0x13d84（自定义波形）  0x13c30（底层）
```

### 3.2 传输通道
```
加密的 2021 端点 0x0090
  OPCM 信封 = 4 字节头 [type, f1, f2, f3] + body
     type==0 才进组分发；组 = f2 & 0x3f（ECF=2）
     body 即 ECF 分发器看到的 payload
调用链：0x140e8(OPCM 接收) → 0x14374(组分发) → 0xc8e0(ECF) → case 0x20
注册结构体首字段 = 0x0090（见 docs/FIRMWARE.md）
```

### 3.3 连接 / 认证（见 docs/PROTOCOL.md）
- BLE + Huami **2021 协议**（分块、可加密）
- 认证：**ECDH (NIST B-163) + AES**，用手机 App 里的 Auth Key
- 经典 `2A06`(Immediate Alert) 在本固件上**被忽略**（写字不报错但不动作）
- `0x0032` "find device"（`0x03`/`0x05`）手环会 **ACK 但不震动**（疑因未装马达波形，待验证）

---

## 4. 建议团队优先做

1. **安全启动 / 固件校验**：`.fw` 头部与 OTA/DFU 路径是否有签名/CRC 校验、能否绕过（决定"能不能刷自研固件"）。
2. **DFU/OTA 入口**：抓一次官方 App 升级流程（HCI snoop），确认刷写通道、分块方式、校验点。
3. **`0x0032` 处理器**：静态确认它是否"播放马达波形槽"。
4. **ECF `0x20` 实测**：在加密 `0x0090` 上构造并发送，验证马达。
5. **MCU/外设画像**：传感器（ICM40608/LSM6DSO/BMI260 字符串已见）、Flash、电源、NFC 控制器。

---

## 5. 复现实验环境（我们这台机器上已验证）

```sh
# 直连手环（需先关掉手机蓝牙，同一时刻只能一条 BLE 连接）
cd ~/Desktop/Self/Mobile/Mi_Band
python3 -m miband2021 --key-file <auth_key.txt> --vibrate --vibrate-seconds 1
```
Auth Key 就在本包的 `AUTH_KEY.txt` 里（本设备专用，别外泄）。

macOS 提示：CoreBluetooth 扫描会"吞"掉已知设备，代码里已用 allow-duplicates 规避（`miband2021/macos_scan.py`）。

---

## 6. 校验和（SHA-256）

```
4b2eee2d307ea89dd9331ca46101f492ccbd86708ede183647e1e9d7ee2630ad  firmware/PANGU_1.0.6.10.fw
454b132f24d50302d15bdad1417aac371efd1648206e4a47f0bc683d949694f5  firmware/PANGU_2.ft
4f8b6c8c0082d0cc93d9c84d1bf2eaf28ea473cfa2c4a6510c828b3d80081441  firmware/PANGU_59.res
62b71ed1828b34b5baa553831dcfe59d88fc5ed8dd4c164f9c8488b5bb0ccc71  original/1.0.6.10_PANGU_202110211347.zip
```

## 7. 免责与合规

- 固件版权归 **小米 / 华米** 所有，此处仅用于**在自有设备上做互操作/研究**。
- **刷机有变砖风险**，务必先做完整备份与恢复预案。
- 不要把设备密钥（Auth Key）外泄或提交到公开仓库。