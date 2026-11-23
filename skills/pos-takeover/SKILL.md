---
name: pos-takeover
description: POS 已拿到 root 或内核 ACE 后做接管判定。Magisk 补 boot、关 vbmeta、Zygisk/DenyList/Shamiko 对抗支付进程 root 检测；或 bootloader/seccfg/SBI 级持久化。
mcps: pos-delivery
---

# 接管判定

前置：已经有 uid=0、自定义内核在跑、DA/fastboot 可写 boot、或 SBI 已 overlay。本 Skill 决定持久化路线，并给出「接管是否成立」。

## 攻击面枚举

1. 再跑 `adb_getprop` + `adb_id_selinux_mounts`（重启后也要跑）。
2. `magisk_feasibility`：`release`、`verifiedboot`、`flash_locked`、`slot_suffix`。
3. 分区：by-name 是否有 `boot`/`boot_a`/`vbmeta`/`seccfg`。
4. 支付进程：`adb_shell` `ps -A` 找 POS/支付包名，只记录，不要杀进程。
5. 来源链：PAX fastboot / Verifone SBI / MTK seccfg / 一次性 LPE。一次性 LPE 重启丢失，必须补持久化。

## 利用假设生成

| 路线 | 适用 | 写入点 |
|---|---|---|
| Magisk boot 修补 | Android 7–15、能写 boot | `magisk_patch_boot` + 之后的 flash/DA 写 |
| 关 AVB / vbmeta | verifiedboot=green 且 locked | flash vbmeta 或外部 disable，proposed |
| Zygisk + DenyList + Shamiko | 支付应用有 root 检测 | 配置级，仍经 Magisk |
| seccfg / DA 持久 | MTK 已控 DA | 重启后仍可写即成立 |
| SBI overlay 持久 | Verifone 链已 overlay | 重启后 H.OUT 仍已认证 |
| 不做 Magisk | 支付应用强检测且 boot 不可写 | 保持 bootloader 级，明确写「无 Android 根隐藏」 |

不要默认「有 root 就装 Magisk」。先看可行性 JSON。

## 逐步验证

只读：

- dump boot 用 `mtk_read` 或（已 root）`adb_shell` 读分区到可拉文件；禁止未批准的回写。
- 记录 Magisk 可行性：`magisk_likely`、`need_vbmeta_disable`、`ab_device`、`hide_stack`。

写入 proposed：

1. `magisk_patch_boot`：`boot_image` 本地 dump 路径，`vbmeta_disable` 按可行性。
2. 修补产物再 `fastboot_flash` 或 `mtk_partition_write`（又一次 proposed）。
3. 重启后：`adb_id_selinux_mounts`、Magisk 是否在、支付进程是否在 DenyList。

隐藏栈只评估，不在 Skill 里塞 Shamiko 安装包。需要安装时走外部服务 `payload_deliver` `stage=magisk-hide`。

## 接管判定

**设备接管成立**（写进结论，满足其一）：

1. 重启后仍有 uid=0 或 Magisk 特权。
2. 重启后 bootloader/DA/SBI 仍允许特权执行，设备对收银界面可正常开机。
3. 支付应用未把测试会话打成「已 root 拒绝交易」——若检测拦了，接管只算「系统特权」，要在结论里写支付进程仍检测成功。

**内核 ACE 但未接管**：有一次性根，重启丢失，持久化 proposed 被拒绝或失败。结论写 ACE 成立 + 接管未完成 + 差哪一步。

输出模板：

```
ace: yes|no
persistent: yes|no
method: magisk|seccfg|sbi|edl-boot|none
hide_from_payment: unknown|likely|blocked
vbmeta: untouched|disable-proposed|disabled
evidence: [工具与回执]
```
