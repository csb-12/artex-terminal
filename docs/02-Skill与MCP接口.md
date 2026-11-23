# Skill 目录与 MCP 接口

本包是独立二开，挂进 ARTEX 后由专用 Agent **终端渗透**（`terminal`）用 Skill 选链、用 MCP 动手。工具名在会话里是 `mcp__pos-delivery__<tool>`。种 Agent 见 `docs/06-终端渗透Agent.md`。

## 1. Skill 目录

挂载后位于 ARTEX `skills/` 下（目录名 = 可见性匹配名）：

```
skills/
  pos-pentest/SKILL.md        主控，按指纹调度
  pos-usb-entry/SKILL.md      USB/ADB/fastboot/EDL/UART 枚举
  pos-pax-fastboot/SKILL.md   CVE-2023-42134
  pos-verifone-sbi/SKILL.md   CVE-2019-14715
  pos-mtk-brom/SKILL.md       BROM + DA + seccfg
  pos-android-lpe/SKILL.md    受限 shell LPE 匹配与投递
  pos-takeover/SKILL.md       Magisk / seccfg / SBI 持久化
```

每个 SKILL.md：

- `name` + `description`（触发词；ARTEX listing 按 UTF-8 字节截到 500，本包均未超）
- `mcps: pos-delivery`（加载 Skill 才解锁该 MCP；未加载时工具不进全局块）
- 正文四段：**攻击面枚举 → 利用假设生成 → 逐步验证 → 接管判定**
- 不内置利用代码

Agent 对 POS 任务应先 `Skill` 工具加载 `pos-pentest`。

## 2. MCP 服务器

| 项 | 值 |
|---|---|
| name | `pos-delivery`（必须与 `mcps:` 一致） |
| 推荐 transport | `http` |
| 宿主机监听 | `http://127.0.0.1:9911` |
| Docker 里的 ARTEX | `http://host.docker.internal:9911` |
| 协议 | MCP Streamable HTTP `2025-06-18` |
| 进程 | `pythonw.exe ...\run_http_9911.py`（`0.0.0.0:9911`） |
| 健康检查 | `GET /health` |

USB 设备挂在 Windows 宿主机，MCP 必须跑在宿主机。容器里起 stdio MCP 看不到 POS。

stdio 备选（ARTEX 与设备同机、不走 Docker）：

- command: `pythonw.exe`
- args: `["C:\\Users\\蒋蒋\\.grok\\bin\\mcp-noconsole.py", "D:\\二开artex\\mcp\\pos-delivery\\server.py"]`

子进程 `CREATE_NO_WINDOW`。禁止 `cmd /k`。

环境变量（给 MCP 进程，不是给 ARTEX 容器）：

| 变量 | 作用 |
|---|---|
| `POS_EXPLOIT_SERVICE_URL` | 外部编译/投递，POST `{url}/compile-deliver` |
| `POS_EXPLOIT_SERVICE_TOKEN` | 可选 Bearer |
| `POS_DELIVERY_SECRET` | proposed token HMAC，不设则进程内随机 |

未配 exploit 服务时 `payload_deliver` 返回 `not_configured` 并回显 cve/stage/target。

## 3. 工具一览

### 3.1 只读 / 模式切换（默认自动）

| 工具 | 作用 |
|---|---|
| `usb_enum` | VID/PID + adb + fastboot |
| `adb_devices` | `adb devices -l` |
| `adb_getprop` | 指纹属性 |
| `adb_id_selinux_mounts` | id / getenforce / mounts / by-name |
| `adb_shell` | 一条侦察命令，禁止 dd 刷分区 |
| `adb_reboot` | bootloader / edl / recovery / system |
| `fastboot_devices` | 列表 |
| `fastboot_getvar` | unlocked/secure/variant 等 |
| `fastboot_oem_help` | 隐藏命令面，不刷机 |
| `uart_list_ports` | COM 列表 |
| `uart_probe` | banner |
| `fingerprint_classify` | vendor/platform + next_skills + hypotheses |
| `cve_match_kernel` | security_patch vs 索引 |
| `cve_match_paydroid` | CVE-2023-42134 型号 |
| `cve_match_verifone` | CVE-2019-14715 型号 |
| `magisk_feasibility` | 7–15 / vbmeta / A/B / hide_stack |
| `mtk_detect` | mtkclient + BROM |
| `mtk_da_info` | DA 只读 GPT |
| `mtk_read` | DA dump 分区到本地 |

### 3.2 写入（无 token → `status=proposed`）

| 工具 | 效果 |
|---|---|
| `fastboot_flashing_unlock` | 解锁，通常清 userdata |
| `fastboot_oem_unlock` | oem unlock |
| `fastboot_flash` | 覆盖分区 |
| `fastboot_erase` | 擦分区 |
| `fastboot_boot_image` | RAM 启动镜像 = 内核级执行 |
| `mtk_seccfg_unlock` | 改 seccfg |
| `mtk_partition_write` | DA 写分区 |
| `mtk_partition_erase` | DA 擦分区 |
| `sbi_overlay` | Verifone SBI 覆盖（转发外部服务） |
| `xdl_upload` | RS232 XDL 上传 |
| `magisk_patch_boot` | 外部服务补 boot |
| `payload_deliver` | 把 CVE/stage/target 交给外部编译投递 |

`proposed` 回包字段：`confirm_token`、`effect`、`reversible=false`、`ttl_sec`（2h）、`args`。带 token 且参数哈希一致才执行。

## 4. 双层写入门

1. MCP 层：写入工具无 token 只提案。
2. ARTEX 拦截：`config/intercept-rules.json` 对写入工具名 `ask`；Bash 里的 `fastboot flash` / mtkclient 写、`adb_shell` 里的 `dd of=` / `reboot` 同样 `ask`。
3. `adb_shell` 本身也会拒绝分区写入和 reboot，改走 `fastboot_*` / `mtk_*` / `adb_reboot`。

指纹、CVE 匹配、路径排序、只读探针：自动。

## 5. CVE 索引位置

`mcp/pos-delivery/data/`：

- `kernel_cve_index.json`
- `paydroid_cve_index.json`
- `verifone_cve_index.json`
- `vidpid.json`

Skill 引用这些文件的结论，不复制 exploit。
