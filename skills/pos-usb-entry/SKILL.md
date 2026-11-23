---
name: pos-usb-entry
description: POS USB 攻击面枚举。adb devices、getprop ro.debuggable/secure/verifiedbootstate/flash.locked、fastboot 变量、MTK BROM VID/PID、高通 9008 EDL、UART 测试点。连接收银机/刷卡机后第一步。
mcps: pos-delivery
---

# POS USB 入口

把插在 Windows 宿主机上的终端识别成可编排攻击面。本 Skill 以只读为主；进 bootloader/EDL 的 reboot 允许，分区擦写不允许。

## 攻击面枚举

按顺序调用：

1. `usb_enum` — VID/PID、adb、fastboot 三份清单。认标签：`adb`、`mtk_brom`（`0e8d:0003`）、`mtk_preloader`、`qcom_edl`（`05c6:9008`）、`sunmi`（`22d9:2769`）。
2. 有 adb 设备且 `state=device`：`adb_getprop`，再 `adb_id_selinux_mounts`。
3. 有 fastboot 设备：`fastboot_getvar`，需要命令面时再 `fastboot_oem_help`。
4. USB 出现 `0e8d:0003` / `2000`：`mtk_detect`；DA 起来后 `mtk_da_info`（只读 GPT）。
5. 授权含物理接触：`uart_list_ports` + `uart_probe`。
6. 把 props / vidpid / fastboot_vars 交给 `fingerprint_classify`。

必读属性：`ro.debuggable`、`ro.secure`、`ro.boot.verifiedbootstate`、`ro.boot.flash.locked`、`ro.boot.vbmeta.device_state`、`ro.build.version.security_patch`、`ro.build.version.release`、`ro.product.model`、`ro.hardware` / `ro.board.platform`。

ADB 只有 `unauthorized`：记为入口缺口，不要停。继续 fastboot 按键、EDL 9008、BROM、UART。

## 利用假设生成

用分类结果填假设，并补入口状态：

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

`adb_reboot` 的 `bootloader` / `edl` 用于切换模式。设备当前是系统且 ADB 可用时，这是进 fastboot/EDL 的合法编排，不是写入。

## 逐步验证

### ADB

- `id`、`getenforce`、`cat /proc/mounts`、`ls /dev/block/by-name`（已由 `adb_id_selinux_mounts` 打包）。
- 可写分区只**记录**，禁止 `dd` 回写。内置拦截会拦 Bash `dd if=`。
- SELinux Enforcing + uid=2000：shell→root 是独立利用阶段，转 `pos-android-lpe`。

### Fastboot

- 记录 `unlocked`、`secure`、`variant`、`slot-suffix`、`version-bootloader`。
- `unlocked=yes`：具备刷写前置，任何 `flash`/`boot`/`erase` 仍走 proposed。
- `unlocked=no`：解锁是可编排步骤。调用 `fastboot_flashing_unlock` **不带 token**，把「通常清 userdata」写进 proposed 说明。

### 高通 EDL（T6920 / MSM8917 主路）

1. USB 已是 `05c6:9008`，或 `adb_reboot` mode=`edl`。
2. 本 MCP 不内置 firehose 程序员。`payload_deliver`：`cve` 填 `qcom-edl`，`stage` 填 `firehose-probe`，`target` 填序列号/型号。
3. 服务未配置：记录缺口「缺 EDL 程序员 / 缺外部服务」，改打 UART 或等实验室服务。
4. 读分区（若服务或后续工具提供只读 dump）优先于写。写 boot/abl 必须 proposed。

### UART

`uart_probe` 看 `root_shell` / `login` / `uboot` / `android` / `unauthenticated`。无认证根壳 = 入口已通。

## 接管判定

本 Skill 本身不宣告接管。出口是一张入口卡，交给主控：

```
vendor / platform / model
adb: missing | unauthorized | shell | root
fastboot: missing | locked | unlocked
brom/edl/uart: 有/无
next_skills[]
hypotheses[]
gaps[]
```

有 root 或无认证特权壳 → 主控加载 `pos-takeover`。否则加载指纹给出的下一条链。
