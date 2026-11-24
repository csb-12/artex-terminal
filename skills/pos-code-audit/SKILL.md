---
name: pos-code-audit
description: 授权 POS 的安卓 APK 与 OS/固件代码审计。事实地图：命令执行/拷贝/格式化/路径/exported。未知不等于安全。补丁对比看修没修完。不把扫描命中当漏洞，不写 PoC。
mcps: pos-delivery
---

# 安卓 / OS 代码审计（事实地图）

对齐 [Treasure Map](https://xz.aliyun.com/news/93403) 的教训：不要让工具或模型给每个函数打「漏洞」标签（一千个误报）；**只把事实整理清楚**，判断由你来写，且必须引用 `evidence_ref`。本节是地图不是扫描交差：读哪条、标哪条、要不要 diff，由你根据覆盖率和业务价值决定。

本 MCP 在 Windows 上可跑（不依赖 Ghidra）。函数级反编译/BinDiff 原生 Windows 做不到：记缺口，有 WSL2 再 `tmap scan/diff`。

工具不输出漏洞结论，不生成 PoC / payload / shellcode。

## 攻击面枚举

来源三选一（都要先有授权）：

1. 设备已 adb `device`：`audit_collect` `{run, serial}` → 只拉厂商前缀 APK（sunmi/pax/…）。
2. 已解包固件 / `adb_pull` 下来的 system：`audit_scan` `{root, run}`。
3. 单个 APK / ELF：`root` 指向该文件。

然后 `audit_list`。默认视图：影响大、又没有被**证明安全**的在前。**未知不会让候选往后排。**

每条候选六层，只有 是 / 否 / 未知（未知带原因）：

| 层 | 字段 |
|---|---|
| 来源 | `external_source` |
| 可控 | `attacker_controlled` |
| 写入者 | `writer_known` |
| 可达 | `reachable` |
| 过滤 | `filtered` |
| 完整 | `analysis_complete` |

安卓额外 kind：`exported`（组件导出）、`jni`、`webview`。OS 额外：`cmd`/`copy`/`fmt`/`path`/`init`/`script`。`secret` 只记「有硬编码片段」，不要把完整密钥贴进会话。

覆盖：`audit_coverage`。没读过标未读，**不标没问题**。必读没判完，审查没结束。

## 利用假设生成

禁止：把 `audit_list` 整表当成漏洞清单；禁止让模型给每个 DEX 字符串写「高危 RCE」。

允许：读图后提出**少数**假设，每条必须能指回 `evidence_ref`。优先：

- exported 组件 + 无 permission（可达仍未知，要在设备上用独立命令验证，不要在 Skill 里写利用代码）
- `system`/`popen`/`Runtime.exec` 且来源未知（去 `audit_get` 看上下文）
- init.rc 以 root 拉起的调试服务
- 两个版本 `audit_diff` 里像修复、但同类调用还在

跨程序问题单独记账：A 写的配置 B 读、谁启动了守护进程。本扫描器不做完整交叉引用时，字段保持未知并写原因。

## 逐步验证

1. `audit_get` 读一条（记已读）。
2. 用不同路径复核：设备上 `dumpsys package`、再拉一份 APK、或对照另一版本。
3. `audit_annotate`：`judgment` + `cites`（事实 ref）。禁止在 judgment 里写 PoC。
4. 补丁：`audit_diff` `{before, after}`，回答四问——是不是安全修复？修完整了吗？别处还有没有？新代码有没有新面？典型没修完：入口断了处理函数还在；缓冲区变大拷贝长度没变；校验只在前端/JS。
5. 函数级对不齐：标未定，不要报删除/新增。深度对比缺口：WSL2 Treasure Map。

证伪要有工具回包。`analysis_complete=unknown` 不是「安全」。

## 接管判定

代码审计本身不是 ACE。只有设备上再次用**不同命令**看到 uid=0 / 可改 boot / 特权守护进程被未授权触发，才转 `pos-takeover`。

终态：

- 地图已画、必读已判、缺口写明（缺 dump / 缺 Ghidra / 缺第二版本）= 审计进度，不是渗透完成
- 标了 incomplete_patch 的条目 = 有效线索，仍要现网复核才算洞
- 禁止用一千条扫描命中交差
