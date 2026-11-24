---
name: pos-verifone-sbi
description: Verifone VX/MX/e355 + RS232/UART 可达时使用。CVE-2019-14715：SBI bootloader XDL 未签名内存写，覆盖 SBI 并把 H.OUT 标为已认证。
mcps: pos-delivery
---

# Verifone SBI 链（CVE-2019-14715）

公开问题：SBI bootloader 经 RS232 XDL 接受未签名内存写，可覆盖正在运行的 SBI，并在内核态把 `H.OUT` 标成已认证，从而持久化自定义可执行文件。本 Skill 不内置 XDL 帧或 overlay 字节。本节是判定地图：进不了 SBI 就换波特率/按键，不要改去刷 Android 分区。

逐步操作模板见仓库 `docs/04-Verifone-SBI验证步骤模板.md`。

## 攻击面枚举

1. 授权必须含物理接触（按键组合 + 串口）。
2. `uart_list_ports` 列本机 COM。
3. `uart_probe` 读 banner（会先打 CR/LF）：SBI / XDL / download / 无认证提示。无输出先换波特率再判死。
4. `cve_match_verifone`：VX520/680/690/820、MX900/915/925、e355。
5. USB 枚举作辅证；本链主入口是 UART/RS232，不是 ADB。

进不了 SBI 下载态：记录按键组合未触发、波特率不对、线序问题，不要改去刷 Android 分区。

## 利用假设生成

| 优先级 | 假设 | 证据 |
|---|---|---|
| 1 | XDL 接受未签名写 | probe 到 XDL/SBI 下载提示，无认证挑战 |
| 2 | 可 overlay SBI 运行时 | 实验室已有 overlay 文件，服务可投递 |
| 3 | 可将 H.OUT 标为已认证 | 覆盖后设备把自定义文件当已签名执行 |

## 逐步验证

只读：

- 固定波特率（默认 115200，失败再按现场文档改 `baud`）。
- 记录 banner 原文、是否 `unauthenticated`、是否像登录壳。

写入（proposed）：

1. `xdl_upload`：`payload_path` 指向实验室文件，`port` 为 COMx。第一次无 token。
2. `sbi_overlay`：同样走外部服务，`cve=CVE-2019-14715`。
3. 无 `POS_EXPLOIT_SERVICE_URL`：停在「SBI 入口已确认，缺 overlay 投递服务」，这仍是有效进度，不是失败瞒报。

不要在 Skill 对话中展开 XDL 协议字段或内存布局。

## 接管判定

成立：

- 自定义 H.OUT 或等价二进制在设备上按已认证逻辑运行。
- 重启后仍在，属于 bootloader 级持久化，转 `pos-takeover` 记录「SBI 级，不必 Magisk」。

证伪：SBI 拒绝未签名写、下载口要密钥、型号有补丁。交回主控。
