# 验证模板：PAX PayDroid fastboot（CVE-2023-42134）

适用：授权清单中的 PAX A920Pro / A920 / A50 / A77 / A80 或 `fingerprint` 含 PayDroid，且 USB fastboot 可达。

本模板是操作顺序，不是 exploit。镜像由实验室目录或 `POS_EXPLOIT_SERVICE_URL` 提供。

## 0. 前置

- [ ] 型号在授权清单，窗口有效
- [ ] 已加载 `pos-pentest` → `pos-usb-entry` → `pos-pax-fastboot`
- [ ] MCP `pos-delivery` 已解锁（Skill 的 `mcps`）

## 1. 只读：进入 fastboot 并采指纹

1. `usb_enum`
2. 若在系统态且 adb 为 `device`：`adb_getprop`，再 `adb_reboot` `mode=bootloader`
3. `fastboot_devices` 确认在线
4. `fastboot_getvar` — 记录 product、variant、unlocked、secure、slot
5. `fastboot_oem_help` — 保存隐藏命令列表原文
6. `cve_match_paydroid` — `model` / `display_id` / `fingerprint`

出口：一张卡，含「隐藏命令面是否存在」「是否仍锁」「是否落在公开影响型号」。

## 2. 假设排序（写进会话，再动手）

| ID | 假设 | 何时升级为当前步 |
|---|---|---|
| P1 | 隐藏命令接受未签名分区覆盖 | oem_help 出现非标准 flash/boot |
| P2 | 可注入内核参数 | 存在 cmdline/bootargs/atag 类变量或 oem |
| P3 | 标准 `fastboot boot` 未验签 | 实验室有测试 boot 镜像 |
| P4 | 已 unlocked 的常规分区写 | `unlocked=yes` |

未命中型号索引：仍可做 P3/P4，结论不得写成「已确认 42134」，只能写「快测」。

## 3. 写入：proposed → 批准 → 执行

对当前假设选一个工具，**第一次不带 token**：

- RAM ACE：`fastboot_boot_image` `{ "image": "<实验室镜像路径>" }`
- 分区覆盖：`fastboot_flash` `{ "partition": "<名>", "image": "<路径>" }`
- 镜像不在本地：`payload_deliver` `{ "cve": "CVE-2023-42134", "stage": "fastboot-hidden-flash", "target": "<serial>" }`

MCP 应返回：

```json
{
  "status": "proposed",
  "confirm_token": "...",
  "effect": "覆盖分区 … / RAM 启动镜像 …",
  "reversible": false
}
```

把 `effect` 给操作者。批准后**同一参数**加 `confirm_token` 再调。

不要在对话输出隐藏命令的 payload 布局或补丁 hex。

## 4. ACE 判定

满足其一即可记「内核 ACE」：

- boot 之后 `adb_id_selinux_mounts` 为 uid=0，或 UART 根壳
- 设备跑实验室 ramdisk/内核（cmdline / uname 与镜像一致）
- 可观察的启动路径分叉（init 进实验室脚本，有日志）

然后加载 `pos-takeover`。PayDroid 支付应用 root 检测单独评估。

## 5. 证伪

- oem_help 无隐藏刷写面，且 `fastboot boot` 被签名拒绝
- 型号明确不在影响面且无等价命令

写证伪，交回主控，改 LPE / 其它入口。
