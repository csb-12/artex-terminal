# 验证模板：Verifone SBI / XDL（CVE-2019-14715）

适用：授权清单中的 VX520/680/690/820、MX900/915/925、e355，授权含物理按键与 RS232。

本模板不包含 XDL 帧格式或 overlay 机器码。

## 0. 前置

- [ ] 型号在授权清单
- [ ] 物理接触已授权
- [ ] Skill：`pos-pentest` → `pos-usb-entry`（串口）→ `pos-verifone-sbi`

## 1. 只读：找到 SBI 下载口

1. 按现场文档做 SBI/下载按键组合（因机型而异，以授权测试说明为准）
2. `uart_list_ports`
3. `uart_probe` `{ "port": "COMx", "baud": 115200 }`
4. 无 banner：换波特率、换口、确认线序，不要改去刷 Android
5. `cve_match_verifone` `{ "model": "<铭牌>" }`

记录：banner 原文、是否 `unauthenticated`、是否明确 XDL/SBI。

## 2. 假设

| ID | 假设 |
|---|---|
| V1 | XDL 接受未签名内存写 |
| V2 | 可 overlay 正在运行的 SBI |
| V3 | 可将 H.OUT 标为已认证并持久化 |

V1 只靠 banner/协议问候即可升到「入口成立」。V2/V3 必须有实验室 payload 文件 + 写入批准。

## 3. 写入：proposed

实验室文件已放在宿主机路径时：

1. `xdl_upload` `{ "payload_path": "<路径>", "port": "COMx" }` 无 token
2. 批准后再带 `confirm_token`
3. 需要覆盖 SBI 运行时：`sbi_overlay` 同样两步
4. 文件由服务生成：`payload_deliver` `{ "cve": "CVE-2019-14715", "stage": "xdl_upload" }`

`POS_EXPLOIT_SERVICE_URL` 未配：停在「SBI 入口已确认，缺投递服务」。这是有效阶段结果。

## 4. 接管判定

成立：

- 自定义 H.OUT（或等价）按已认证逻辑执行
- 重启后仍在 → bootloader 级持久化，`pos-takeover` 方法填 `sbi`，不必强行 Magisk

证伪：下载口要密钥、拒绝未签名写、型号已补丁。
