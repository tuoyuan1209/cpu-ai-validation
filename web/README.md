# CPU Validation Center V3.0 — 私有 Web 控制台

独立网页，不修改 OpenHands 官方前端，不替换现有两个 Git 仓库。直接兼容已交付的 CPU Validation V2.0 `scripts/run_stage.py`。本版采用原生 HTML/CSS/JS + Python HTTP 服务，避免 Node 构建及额外框架安装；需要 Python 3.10+ 和现有 PyYAML。

## 目录和启动（与你当前 Docker 环境对应）

把 `cpu_validation_web_v3.tar.gz` 下载到 `/home/teemo/project/teemo_project`，在宿主机执行：

```bash
cd /home/teemo/project/teemo_project
tar -xzf cpu_validation_web_v3.tar.gz
docker exec -it openhands-ubuntu24 bash
```

在容器内启动（保持这个终端运行；建议使用 tmux 持久终端，如果已安装）：

```bash
cd /home/teemo/project/teemo_project/cpu-validation-web
WEB_BIND=0.0.0.0 bash start.sh
```

依次输入网页 operator 密码（至少12字符、不要复用 SUT 密码）、SUT sudo 密码、OpenHands session API key（如后端明确无需认证可留空）。不在项目中写入这些值。不要把 Secret 发到聊天、Git 或命令行参数中。OpenHands session key 不等同于 GitHub PAT，也不等同于 SUT 密码。

启动后，在另一宿主机终端取得容器 IP：

```bash
docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' openhands-ubuntu24
```

在这台 Linux 宿主机的浏览器打开 `http://实际容器IP:8080`，用户名 `operator`，密码为启动时输入的网页密码。默认不新增 Docker 公网端口映射。若使用 host network，可尝试 `http://127.0.0.1:8080`。Docker bridge 通常可由 Linux 宿主访问，但实际网络策略可能不同。若不通，检查 `docker inspect` 网络模式及端口；不要直接关闭防火墙。

**安全边界：这是单操作员私有部署版本，不是多用户生产系统。** 默认 `start.sh` 只监听 127.0.0.1，上述 `WEB_BIND=0.0.0.0` 仅为现有 Linux Docker 私有桥接访问，确保 8080 未对外发布、容器不使用不受信任网络。HTTP Basic Auth 在无 TLS 情况下只可用于可信本机网络；远程访问应使用 SSH 隧道或 HTTPS 反向代理，并增加独立账户与权限管理。不要把容器端口暴露给互联网。后端进程可访问 SUT 和 OpenHands，因此其权限较高。密码及 key 仅在环境变量中，不保证对 root/进程管理者隐藏。

## OpenHands API

默认 `OH_AUTOMATION_URL=http://127.0.0.1:8001/api/automation/v1`，根据官方本地 Canvas Automation 文档；此端口是否属于你实际的 1.35.0 Automation 后端，需在部署后确认。页面“任务执行 → 检查 OpenHands API / 任务列表”只发 GET 请求。API 支持手动触发 `POST /{id}/dispatch` 及运行列表 `GET /{id}/runs`。适配器使用 `X-Session-API-Key` 请求头，拒绝重定向。

若列表检查失败，在容器另一个终端运行 `ss -lntp` 查实际端口；以官方 Canvas 当前 backend 的实际 API 地址为准。可覆盖：

```bash
OH_AUTOMATION_URL=http://127.0.0.1:实际端口/api/automation/v1 WEB_BIND=0.0.0.0 bash start.sh
```

不要在 URL 中嵌入密码或 Token。默认 API 地址不是通过真实设备探测得出的。API 的返回字段如与当前版本不同，程序会报错，不自动猜测任务或重复派发。未知派发需在官方 Canvas 核实后使用网页“人工解除未知派发状态”。

参考官方文档： https://github.com/OpenHands/extensions/blob/main/skills/openhands-automation/SKILL.md

普通任务默认选 OpenHands 模式，使用实际服务器返回的任务 ID，检查名称唯一、启用状态、服务器 Prompt 与本地仓库模板一致后才派发。不自动创建/启用任务，不自动批准，不变更定时计划。CPU-00兼容已有 `CPU-00-Discovery-Automation` 名称。必须保持官方 Canvas 中的模型、Local 环境、Secret及定时策略正确；本版不会替你确认远程 bundle 与模型配置完全一致。OpenHands 模式需要原有 Automation 仓库完整、已同步。

若暂时无法连通 API，可明确选择“固定 Python 引擎”，直接运行相同 `run_stage.py`，不会静默降级。人工审批和长测始终使用固定引擎。官方 Canvas 保留用于 Agent 调试、任务配置、Git Sync 及查看对话。

## 推荐使用流程

1. 任务执行：CPU-01、CPU-00；先检查 OpenHands API，或者明确选固定引擎。环境探测成功后才可审批。
2. 验收配置与审批：对照实际供应商文件及候选配置；确认 CPU 6 或其他隔离核心、Guest 用户、延迟阈值等。网页只允许编辑测试核心、Guest 用户/MAC/IP、阈值及两个负载授权开关，核心分区和 VM 绑定保持现有正式策略。如需修改正式架构，管理员维护 `isolation_policy.yaml` 后刷新。
3. 只有实际获授权才能勾选 CPU/KVM 压力和 I/O 压力。未授权保持关闭。保存后旧审批失效。最大延迟没有正式标准时留空，不把缺失标准作为通过。
4. 填写真实规格版本/工单编号、勾选人工审核并确认。后端检查审查摘要未变化、候选证据校验，然后调用现有 `run_stage.py approve --reviewed`。真实审批记录位于引擎 `.validation/`；网页审计记录位于 `.web-state/audit.jsonl`。网页显示“已审批”指本地配置/代码哈希一致，执行时引擎还会核验目标机指纹。
5. 启动完整短测 workflow（默认 OpenHands）；或者单阶段执行。所有任务调用固定白名单，不接受任意 shell 命令。每次执行都需要明确确认。
6. 连续60分钟测试选 CPU-08（固定引擎），或者“完整流程含长测”。两者不会走1800秒 Agent 超时。后端独立子进程执行，浏览器关闭不终止；必须保证容器及 Web 服务持续运行。当前版本不提供远程取消按钮和自动恢复任务监控；服务重启后历史证据仍在，若长测未结束，V2引擎锁会阻止其他测试。不要强杀或并发运行测试。
7. CPU-09生成报告。短测未包含CPU-08或缺失验收标准可能为 INCONCLUSIVE。OpenHands COMPLETED/本地进程退出不是正式 PASS，必须看实际 `result.json`/`report.md`。

## 审批与并发设计

- 复用 V2 审批哈希、目标机指纹和引擎文件锁，不创建虚假审批会话。
- 网页审查摘要绑定本地代码、策略、连接配置和最新成功候选文件；策略更新须通过 V2 validate，写入采用原子替换。
- 网页拒绝无批准会话的正式测试。OpenHands 派发后记录待处理状态，未知响应不自动重试；必须人工核对。引擎锁保护同时启动的脚本，但网页不能阻止管理员通过外部 Canvas/终端排队或直接编辑文件。使用网页时请停用旧定时任务，不从其他入口同时触发，也不要在审批/运行中外部改策略。
- 审计记录为普通本地日志，非不可篡改审计；本版没有多人审批、RBAC或电子签章。
- 本地子进程记录退出码和日志，报告直接读取已有证据，不生成虚假指标。全局日志每3秒刷新；未实现 WebSocket 或结构化实时 Agent 事件流。
- API 任务列表/触发适配器仅按公开文档实现，尚未连接你真实的 Canvas 后端；如果版本字段或鉴权方式不同，需要结合实际 OpenAPI 或网络请求调整，不承诺一次接通。

## 开发测试

```bash
python3 -m unittest discover -s tests -v
python3 -m py_compile server.py
node --check static/app.js  # 如已安装 Node
```

测试使用本地模拟 HTTP 服务和模拟 OpenHands API，不访问真实 SUT，不施加负载，不调用真实 dispatch。`.web-state`、Secret、日志和审批结果不得提交 Git。保留原两个仓库，本网页可以作为第三个独立 Git 仓库管理。
