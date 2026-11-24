---
name: pos-usb-entry
description: POS USB 攻击面枚举。adb devices、getprop、fastboot 变量、MTK BROM VID/PID、高通 9008 EDL、9006 诊断口、UART 测试点。ADB unauthorized 不是停手。连接收银机/刷卡机后第一步。
mcps: pos-delivery
---

# POS USB 入口

把插在 Windows 宿主机上的终端识别成可编排攻击面。本 Skill 以只读为主；进 bootloader/EDL 的 reboot 允许，分区擦写不允许。

本节是判定与工具地图，不是打勾清单。先广后聚：先把 adb / fastboot / EDL / BROM / UART 摸清，再选链。一条入口试一次失败要换模式再判死。下一步由你根据回包决定。

## 入口探针（按现场有什么打什么）

必做：`usb_enum`（VID/PID、adb、fastboot 三份清单）。认标签：`adb`、`fastboot`、`mtk_brom`（`0e8d:0003`）、`mtk_preloader`、`qcom_edl`（`05c6:9008`）、`qcom_diag`（`05c6:9006`）、`sunmi`（`22d9:2769`）。回包里的 `vidpid` / `tags` 原样交给分类器。

其余按回包决定，空的接口不要打：

- 有 adb 且 `state=device`：`adb_getprop`，再 `adb_id_selinux_mounts`，再 `adb_surface`。
- 有 fastboot：`fastboot_getvar`，需要命令面时再 `fastboot_oem_help`。
- USB 出现 `0e8d:0003` / `2000`：`mtk_detect`；DA 起来后 `mtk_da_info`（只读 GPT）。
- USB 出现 `05c6:9008` 或商米高通：`edl_programmer_hint`（只给 firehose 文件名）。
- 授权含物理接触：`uart_list_ports` + `uart_probe`（会先打 CR/LF 唤醒 banner）。
- 材料够了：把 props / vidpid / fastboot_vars / adb_state / usb_tags 交给 `fingerprint_classify`。分类结果是假设目录，不是命令。

必读属性（有 getprop 才读）：`ro.debuggable`、`ro.secure`、`ro.boot.verifiedbootstate`、`ro.boot.flash.locked`、`ro.boot.vbmeta.device_state`、`ro.build.version.security_patch`、`ro.build.version.release`、`ro.product.model`、`ro.hardware` / `ro.board.platform`、`persist.sys.usb.config`。

ADB 只有 `unauthorized`：记为入口缺口，**不要停**。继续 fastboot 按键、EDL 9008、BROM、UART。MDM 把设置里 ADB 灰掉是 POS 常态，不是结束。

## 利用假设生成

用分类结果填假设，并按现场证据改优先级：

| 观察 | 假设 |
|---|---|
| adb `uid=0` | 已是 root，转 `pos-takeover` |
| adb shell 且 uid≠0 | `adb-shell-to-lpe` → `pos-android-lpe` |
| `ro.debuggable=1` 且可 `adb root` | 先尝试提权到 adbd root（只读验证 `id`），成功则接管 |
| fastboot 在线 + PayDroid/PAX | `pos-pax-fastboot` |
| `0e8d:0003` 或 platform=mtk | `pos-mtk-brom` |
| `05c6:9008` 或商米高通 | `qcom-edl-firehose`（本 Skill 继续） |
| 串口 banner 含 SBI/XDL/Verifone | `pos-verifone-sbi` |
| UART 无认证 root/uboot | 直接当特权壳，转接管判定 |
| 联迪/Ingenico/新大陆 无专属链 | 通用 USB+UART，缺口写明，不伪造 CVE |

`adb_reboot` 的 `bootloader` / `edl` 用于切换模式。设备当前是系统且 ADB 可用时，这是进 fastboot/EDL 的合法编排，不是写入。

## 逐步验证

### ADB

- `id`、`getenforce`、`cat /proc/mounts`、`ls /dev/block/by-name`（已由 `adb_id_selinux_mounts` 打包）。
- `adb_surface` 一次取：uname、包名、USB 配置、`/dev/video*` `/dev/kgsl*` `/dev/mali*`、监听口。
- 可写分区只**记录**，禁止 `dd` 回写。内置拦截会拦 Bash `dd if=`。
- SELinux Enforcing + uid=2000：shell→root 是独立利用阶段，转 `pos-android-lpe`。

### Fastboot

- 记录 `unlocked`、`secure`、`variant`、`slot-suffix`、`version-bootloader`。
- `unlocked=yes`：具备刷写前置，任何 `flash`/`boot`/`erase` 仍走 proposed。
- `unlocked=no`：解锁是可编排步骤。调用 `fastboot_flashing_unlock` **不带 token**，把「通常清 userdata」写进 proposed 说明。

### 高通 EDL（T6920 / MSM8917 在指纹对上时的主路）

现场已是 `05c6:9008`，或你判断该进 EDL 时 `adb_reboot` mode=`edl`。然后：

1. `edl_programmer_hint` 记下 `prog_emmc_firehose_8917*.mbn` 这类**文件名**。本 MCP 不内置 firehose 程序员。
2. `payload_deliver`：`cve` 填 `qcom-edl`，`stage` 填 `firehose-probe`，`target` 填序列号/型号。
3. 服务未配置：记录缺口「缺 EDL 程序员 / 缺外部服务」，改打 UART 或等实验室服务。这是有效进度。
4. 读分区优先于写。写 boot/abl 必须 proposed。

不是高通就不要套这棵树。

### UART

`uart_probe` 看 `root_shell` / `login` / `uboot` / `android` / `unauthenticated`。无 banner 先换波特率再判死。无认证根壳 = 入口已通。

## 接管判定

本 Skill 本身不宣告接管。出口是一张入口卡，交给你自己排后续：

```
vendor / platform / model
adb: missing | unauthorized | shell | root
fastboot: missing | locked | unlocked
brom/edl/uart: 有/无
next_skills[]   （建议）
hypotheses[]    （建议）
gaps[]
```

有 root 或无认证特权壳 → 加载 `pos-takeover`。否则按你排的优先级加载下一条链 Skill。
