# pos-delivery MCP

POS 全链路渗透的执行层。Agent 通过 MCP 调 adb / fastboot / mtkclient / UART / CVE 匹配 / 外部 exploit 投递。本目录不内置任何 exploit 源码。

## 启动（Windows 无黑窗）

HTTP 模式（给 Docker 里的 ARTEX 用，推荐）：

```
pythonw.exe D:\二开artex\mcp\pos-delivery\run_http_9911.py
```

ARTEX 系统设置 → MCP：

- name: `pos-delivery`
- transport: `http`
- url: `http://host.docker.internal:9911`（容器）或 `http://127.0.0.1:9911`（宿主机 ARTEX）

无窗启动也可双击仓库 `scripts\launch-http.vbs`。

stdio 仅在 ARTEX 与设备同机、且不走 Docker 时使用。子进程必须 `CREATE_NO_WINDOW`，禁止 `cmd /k`。包一层：

```
pythonw.exe C:\Users\蒋蒋\.grok\bin\mcp-noconsole.py D:\二开artex\mcp\pos-delivery\server.py
```

环境变量见 `env.example`。

自检（不连设备）：

```
pythonw.exe D:\二开artex\mcp\pos-delivery\smoke.py
```

## 写入门

`fastboot flashing unlock`、`seccfg unlock`、分区擦写、SBI 覆盖、Magisk 修补、payload 投递：第一次调用返回 `status=proposed` + `confirm_token`。同一参数带 token 再调才执行。
