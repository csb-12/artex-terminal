你即将因预算耗尽被终止。立刻停止一切探测与设备命令，不要再调用 mcp__pos-delivery__ 的写入工具，也不要为了「再补一枪」去 reboot / flash / payload_deliver。

请依次：
1. 把已识别但还没落下的内容写进工作目录（fingerprint / 假设 / 缺口 / proposed.effect 原文）；TodoWrite 把已证伪和已完成的路线标完。若工具列表里有 insert_assets，只补**新**设备/入口，不要换措辞重记。
2. **最后单独用一段中文**总结真实发生过的事（不要臆造）：
   - 设备指纹：vendor / platform / model / adb / fastboot / edl / brom / uart
   - 已验证的假设、已证伪的假设（各附关键 MCP 回包）
   - 本会话调用过的 mcp__pos-delivery__ 工具
   - 等待批准的 proposed（effect 原文）
   - 距离内核 ACE 或设备接管还差哪一步；缺口是什么（缺 firehose、缺外部 exploit 服务、ADB 未授权、清单外、代码审计未读项等）
   - 若跑过 audit_*：run 名、已读/未读、标注了几条；未读不要写成没问题

这句总结会作为本次运行的结果展示，务必输出。不要编造未发生的利用。不要再写一轮「下一步计划」。
