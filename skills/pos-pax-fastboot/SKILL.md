---
name: pos-pax-fastboot
description: PAX PayDroid + USB fastboot 可达时使用。CVE-2023-42134：fastboot 隐藏命令未签名分区覆盖与内核参数注入，目标 A920Pro/A50/A77/A80。验证到内核 ACE。
mcps: pos-delivery
---

# PAX PayDroid fastboot 链（CVE-2023-42134）

公开问题：PayDroid 在 fastboot 暴露隐藏命令，可覆盖未签名分区并向内核注入参数，从而在 fastboot 阶段拿到任意代码执行。本 Skill 只编排验证，**不内置命令字节、补丁或 boot 镜像**。

逐步操作模板见仓库 `docs/03-PAX-fastboot验证步骤模板.md`。

## 攻击面枚举

1. `usb_enum` / `fastboot_devices` 确认 fastboot 在线。系统态则 `adb_getprop` 后 `adb_reboot` → `bootloader`。
2. `fastboot_getvar`：product / variant / unlocked / secure / version-bootloader。
3. `fastboot_oem_help`：只读探测 `oem help` / `oem ?` / `help`。把回包里的隐藏子命令原样记录。
4. `cve_match_paydroid`：型号、`ro.build.display.id`、fingerprint。命中 A920Pro / A920 / A50 / A77 / A80 / PayDroid 才把本 CVE 提到 P1。

未进 fastboot：回到 `pos-usb-entry`，不要在系统态猜隐藏命令。

## 利用假设生成

按证据排序：

| 优先级 | 假设 | 需要的证据 |
|---|---|---|
| 1 | 隐藏 flash/boot 接受未签名镜像 | oem_help 或 getvar 暴露非标准分区/boot 命令 |
| 2 | 内核 cmdline 可被 fastboot 变量改写 | 存在 `cmdline` / `atag` / `bootargs` 类变量或 oem 命令 |
| 3 | 官方 `fastboot boot` 未校验签名 | `fastboot_boot_image` 对实验室镜像 proposed |
| 4 | 设备已 unlocked，标准分区可写 | `unlocked=yes`，仍要 proposed 才 flash |

每条假设写清：预期 ACE 形态（RAM 启动自定义内核 / 持久分区被换 / init 以 root 起 shell）。

## 逐步验证

只读阶段（自动）：

- 保存 `fastboot_getvar` 与 `fastboot_oem_help` 全文。
- 对比 `cve_match_paydroid.candidates`。无命中则降级为「型号外快测」，不要当 42134 已确认。

写入阶段（必须 proposed）：

1. 第一次调用 `fastboot_boot_image` 或 `fastboot_flash` **不带** `confirm_token`。
2. 把返回的 `effect`（覆盖哪一块、是否可逆）交给操作者。
3. 批准后同一 `partition`/`image` 加 token 执行。
4. 镜像来自实验室：`payload_deliver`，`cve=CVE-2023-42134`，`stage` 为 `fastboot-hidden-flash` 或 `kernel-arg-inject`。MCP 不生成镜像。

禁止在对话里写出 exploit 源码、补丁 hex、具体隐藏命令的 payload 布局。实验室镜像用文件路径传入 MCP。

## 接管判定

ACE 成立（满足其一）：

- `fastboot boot` 或隐藏 boot 之后出现 adb root / 串口根壳。
- 未签名分区写入后重启，设备跑实验室内核或带调试 cmdline。
- 能在 fastboot 改写内核参数并观察到启动路径分叉（例如 init 进实验室 ramdisk）。

随后加载 `pos-takeover`。评估 PayDroid 支付应用对 Magisk/Zygisk 的检测；必要时 bootloader 级持久化优先于 Magisk。

证伪：隐藏命令面不存在、签名强制失败且无 bypass、型号不在索引且无等价命令。写证伪原因，交回主控下一条假设。
