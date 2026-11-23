---
name: pos-android-lpe
description: POS 仅有受限 adb shell、uid 非 0 时使用。按 ro.build.version.security_patch 匹配 CVE-2024-53104/31317/23380 等内核/Zygote LPE，经外部服务投递，Skill 不内置利用代码。
mcps: pos-delivery
---

# Android 受限 shell → LPE

前置：`pos-usb-entry` 已证明 adb shell 可用且 `uid≠0`。本 Skill 产出 CVE 匹配、验证命令、投递接口；**不把 exploit 写进对话或仓库**。

## 攻击面枚举

1. 确认 `adb_id_selinux_mounts`：uid、gid、context、getenforce。
2. `adb_getprop`：`ro.build.version.security_patch`、`release`、`sdk`、platform。
3. 只读看利用前置（用 `adb_shell`，一条命令一次）：
   - UVC：`ls /dev/video*`、`lsmod`
   - GPU：`ls /dev/kgsl-3d0`、`ls /dev/mali*`
   - Binder：`ls /dev/binder*`
   - 内核：`uname -a`
4. `cve_match_kernel` 传入 `security_patch`、`kernel_release`、`platform`、`has_uvc`。

索引里当前条目（日期以 `android_patch` 为准，设备 patch **早于**该日才加分）：

| CVE | 面 | 备注 |
|---|---|---|
| CVE-2024-53104 | UVC 越界写 | 需要 camera/UVC 节点 |
| CVE-2024-31317 | Zygote specifyIds | framework，不依赖内核驱动 |
| CVE-2024-23380 | 高通 GPU | platform=qcom |
| CVE-2023-6241 | Mali | platform=mtk |
| CVE-2022-20409 | Binder UAF | 老补丁窗口，Android 7 商米常见 |

T6920（Android ~7）对 2024 年补丁窗口通常仍「未修」，但 UVC/Zygote 利用前置可能缺失。Binder/老内核候选不要丢掉。

## 利用假设生成

把 `candidates` 按 `score` 排序，输出给操作者：

```
CVE
score / reasons
impact
verify[]（已跑的命令结果）
mcp_deliver = payload_deliver
exploit_in_skill = false
```

score≤0 的条目不当候选。有前置缺失（例如 needs_uvc 但没有 /dev/video）就降优先，不要删除。

## 逐步验证

1. 先跑索引里的 `verify` 命令，把存在/不存在记实。
2. 选当前最高分 CVE，调用 `payload_deliver` **无 token**：`cve`、`stage=lpe-from-adb`、`target=serial`。
3. 返回 `not_configured`：缺口挂「外部编译投递服务」，改下一条 CVE 或回到 EDL/fastboot 链。
4. 服务已配置且操作者批准 token：再调一次，等待服务回执。成功标准是设备上出现 uid=0 或内核模块加载证据，由服务回执 + 本机 `adb_id_selinux_mounts` 复核。

禁止：在 SKILL 或对话生成 C 代码、exploit PoC、内核补丁。禁止用 Bash 编译。

## 接管判定

`id` 变为 `uid=0` 或等价内核 ACE → `pos-takeover`。

全部候选因补丁日期已修、前置不存在、服务未配置而停：主控切回 USB 其它入口（EDL / fastboot / UART），不要宣告「无法利用」。
