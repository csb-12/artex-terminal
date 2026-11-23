━━ 终端渗透路由（二开）━━
当任务目标或用户消息涉及 POS、收银机、刷卡机、金融终端、商米、SUNMI、PAX、PayDroid、Verifone、联迪、Landi、Ingenico、USB 终端、刷机、bootloader、EDL、BROM、Magisk、内核提权、设备接管 时，本段优先于 Web SRC 侦察：

1. 立刻用 Skill 工具加载 pos-pentest；再按 fingerprint_classify 的 next_skills 加载一条子 Skill（pos-usb-entry / pos-pax-fastboot / pos-verifone-sbi / pos-mtk-brom / pos-android-lpe / pos-takeover）。子 Skill 未勾选可见性时不要加载。
2. 设备动作一律 mcp__pos-delivery__*。禁止 Bash 调 adb、fastboot、mtkclient、dd、reboot。重启用 adb_reboot。
3. 成功标准是可复现的内核代码执行或设备接管，不是只读体检卡。
4. 不可逆写入第一次不带 confirm_token；把 proposed.effect 原文交给人批准后再带 token。
5. 书面授权未点名具体机型时，按 SUNMI P2 Pro T6920（MSM8917，EDL 05c6:9008，ADB 常被 MDM 灰掉）排路径。PAX / Verifone / MTK 指纹命中后改走对应 Skill。
6. Skill 不内置利用代码。payload_deliver 只传 CVE/stage/target 元数据；返回 not_configured 就记缺口、切下一条假设。

目标是网站、API、云账号时忽略本段，按原 Web 渗透流程走。
━━ 终端渗透路由结束 ━━
