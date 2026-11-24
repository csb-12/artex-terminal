---
name: pos-android-lpe
description: POS 仅有受限 adb shell、uid 非 0 时使用。按 security_patch 与驱动节点匹配 DirtyCOW/Binder/UVC/Zygote/GPU LPE。POS OEM 补丁日期常虚高。经外部服务投递，不内置利用代码。
mcps: pos-delivery
---

# Android 受限 shell → LPE

前置：adb shell 可用且 `uid≠0`。本 Skill 产出 CVE 匹配、验证命令、投递接口；**不把 exploit 写进对话或仓库**。本节是判定地图，不是打勾清单。

CVE 命中不是漏洞。`security_patch` 在商米等 OEM 上经常虚高（改了日期没合补丁），必须用 `uname` 和驱动节点复核。先打哪条 CVE 由你根据 `score` 和现场节点决定。

## 攻击面枚举

缺什么补什么，不要重复已有回包：

- uid / SELinux：`adb_id_selinux_mounts`
- 补丁与版本：`adb_getprop`（`security_patch` / `release` / `sdk` / platform）
- 驱动节点：`adb_surface`（uname、`/dev/video*`、`/dev/kgsl*`、`/dev/mali*`、`/dev/binder*`）。不要一条条 `adb_shell` 重复打。
- 匹配：`cve_match_kernel` 传入 `security_patch`、`kernel_release`、`platform`、`android_release`、`has_uvc` / `has_kgsl` / `has_mali`（用 surface 的 flags）。

索引里当前条目（日期以 `android_patch` 为准；日期声称已修仍可能因内核版本被保留）：

| CVE | 面 | 备注 |
|---|---|---|
| CVE-2016-5195 | Dirty COW | Android 7 / kernel 3.18 商米优先候选 |
| CVE-2022-20409 | Binder UAF | 老补丁窗口 |
| CVE-2019-2215 | Binder UAF | Android 8–10，不要套 Android 7 |
| CVE-2023-20938 | Binder UAF | 较新窗口 |
| CVE-2024-53104 | UVC 越界写 | 需要 camera/UVC 节点 |
| CVE-2024-31317 | Zygote specifyIds | Android 9+ framework |
| CVE-2024-23380 / CVE-2022-22057 | 高通 GPU | 需要 `/dev/kgsl-3d0` |
| CVE-2023-6241 / CVE-2022-38181 | Mali | 需要 `/dev/mali*`，不套高通 |
| CVE-2020-0069 | MTK cmdq | platform=mtk |

T6920（Android ~7，kernel 3.18）优先 DirtyCOW / 老 Binder；2024 UVC/Zygote 前置经常缺失。

## 利用假设生成

把 `candidates` 按 `score` 排序，你自己选先打哪条（不必从第一行念到最后）：

```
CVE
score / reasons
impact
verify[]（已跑的命令结果）
mcp_deliver = payload_deliver
exploit_in_skill = false
```

score≤0 的条目不当候选。有前置缺失（例如 needs_uvc 但没有 /dev/video）就降优先或由匹配器直接丢掉。一条 CVE `not_configured` 不等于整条 LPE 死路——切下一条候选。

## 逐步验证

1. 先跑索引里的 `verify` 命令（surface 已覆盖的不要重复）。
2. 选当前最高分 CVE，调用 `payload_deliver` **无 token**：`cve`、`stage=lpe-from-adb`、`target=serial`。
3. 返回 `not_configured`：缺口挂「外部编译投递服务」，改下一条 CVE 或回到 EDL/fastboot 链。
4. 服务已配置且操作者批准 token：再调一次，等待服务回执。成功标准是设备上出现 uid=0 或内核模块加载证据，由服务回执 + 本机 `adb_id_selinux_mounts` **用与首次不同的命令**复核。

禁止：在 SKILL 或对话生成 C 代码、exploit PoC、内核补丁。禁止用 Bash 编译。

## 接管判定

`id` 变为 `uid=0` 或等价内核 ACE → `pos-takeover`。一次性 LPE 重启丢失，接管 Skill 必须补持久化。

全部候选因前置不存在、服务未配置而停：主控切回 USB 其它入口（EDL / fastboot / UART），不要宣告「无法利用」。
