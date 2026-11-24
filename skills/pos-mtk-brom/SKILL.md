---
name: pos-mtk-brom
description: 联发科 POS 进入 BROM/Preloader（VID 0e8d:0003）时使用。Kamakiri + mtkclient DA 任意读写、seccfg unlock、RPMB/分区操作。bootloader 解锁是可编排步骤。
mcps: pos-delivery
---

# MTK BROM / DA 链

目标：BROM 阶段拿到 DA，评估分区任意读写、`seccfg` 改锁状态、boot 分区可写。MCP 只包装 **mtkclient CLI**，不内置 Kamakiri 源码或 payload。本节是判定地图：detect 失败先换短接/线序再判死，不要空转 printgpt。

## 攻击面枚举

1. `usb_enum` 看 `0e8d:0003`（BROM）、`0e8d:2000` / `20ff`（Preloader）。
2. `mtk_detect`：本机是否有 `mtk` / `pythonw -m mtkclient`，能否 `printgpt`。
3. `mtk_da_info`：只读 GPT。记下 `boot`/`boot_a`/`seccfg`/`vbmeta`/`lk`/`recovery` 是否出现。
4. 需要备份时 `mtk_read`（只读 dump 到本地路径）。dump 不是写入。
5. 若设备仍在系统态：`adb_getprop` 看 platform 是否 mt67/mt65/mt68/mt87。

BROM 需要短接测试点时，确认授权含物理接触。

## 利用假设生成

| 优先级 | 假设 | 说明 |
|---|---|---|
| 1 | Kamakiri 类 BROM 绕过已可用 | mtkclient 能进 DA（detect/da_info 成功即强证据） |
| 2 | DA 任意读 | `mtk_read` 能拉 boot/seccfg |
| 3 | DA 任意写 | `mtk_partition_write` proposed |
| 4 | `seccfg unlock` 改锁状态 | 重启后仍像 locked 但可刷，或解锁持久 |
| 5 | RPMB/seccfg 加密变体 | 只读探测失败时记缺口，不要伪造成功 |

bootloader 解锁是正向步骤，不要因为「会解锁」就停。停的条件只有：不在授权清单，或操作者拒绝 proposed。

## 逐步验证

只读自动：detect → da_info → 按需 read `boot` 或 `boot_a`、`seccfg`。

写入必须 proposed，每次一条：

- `mtk_seccfg_unlock` — 改 seccfg，可能改变 lock 外观。
- `mtk_partition_write` — 指定 partition + image。
- `mtk_partition_erase` — 擦除。

实验室镜像：`payload_deliver`，`cve` 用 `mtk-kamakiri` 或具体编号，`stage` 用 `brom-da` / `seccfg-unlock` / `boot-write`。

mtkclient 不在 PATH：记录缺口，提示在宿主机安装 mtkclient，并用 pythonw 调用（禁止弹控制台）。不要改去让 Agent 用 Bash 跑 `python mtk.py`。

## 接管判定

成立：

- DA 已写 boot 且设备用实验室 ramdisk/内核启动，或出现 root 壳。
- seccfg 修改在重启后仍允许刷写，设备对支付应用仍显示 locked（记录为 bootloader 级隐匿持久化）。

然后 `pos-takeover`。Magisk 是否可行看 Android 版本与 vbmeta，用 `magisk_feasibility`，不要默认刷 Magisk。
