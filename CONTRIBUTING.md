# 贡献

感谢你愿意改进这个二开包。请先跑：

```bash
python scripts/bootstrap-terminal-agent.py --self-check
python mcp/pos-delivery/smoke.py
```

## 接受什么

- 指纹 / VID-PID / CVE **索引**（结论级，不要 exploit）
- MCP 只读探针、写入门、Windows 无窗启动
- Skill / Agent 人格：让模型更能自主判断，而不是更长的打勾清单
- 文档里的本机路径、错误的默认机型假设

## 不接受什么

- exploit 源码、PoC、未签名镜像、firehose 程序员本体
- 把 `/app/skills` 整卷 overlay 掉 `api-recon` / `bytesrc`
- 把分类器写成指挥官（`只加载 next_skills[0]`、每轮五段状态报告）
- 真实密码、token、任务抓包、授权清单外的目标

## Skill 约定

- 目录名 = frontmatter `name`，必须有 `mcps: pos-delivery`
- `description` UTF-8 不超过 500 字节（ARTEX listing 会截断）
- 正文是判定地图，不是逐步念完的剧本
- 自定义 Agent 提示词里禁止 `{{`（渲染会失败）

## 本地路径

公开文件不要写死某台机器的用户名或 `D:\...`。Skill 挂载用 `${ERKA_ROOT}`，本机路径由 `python scripts/bootstrap-terminal-agent.py --init` 写进已 gitignore 的 `config/.compose.env`。
