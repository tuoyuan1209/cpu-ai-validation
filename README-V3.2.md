# CPU 验收平台 V3.2（基于上传的 V2/V3.1 源码）

## 安装
先确认 Canvas 无排队或运行任务、无本地长测，停止网页进程；不要在运行中升级。解包到独立 staging 目录（不要直接覆盖仓库），执行 `python3 install_v32.py --target /home/teemo/project/teemo_project/cpu_ai_validation` 预检，增加 `--apply` 安装。输出 BACKUP 是回滚路径；同一个脚本 `--target ... --rollback <BACKUP>` 恢复补丁涉及的代码（若升级后又改动文件则拒绝覆盖）。另一个包同样安装到 openhands-automations。备份只包含被替换代码，不修改 config.yaml、isolation_policy.yaml、provision_policy.yaml、.validation、.web-state、runs、logs 或密钥。升级前的正式策略不能直接复用旧审批；新流程会重建批准会话。若要完全恢复升级前运行状态，应在停机时自行另行备份状态目录；不要用旧审批绕过校验。

## 启动与验收
容器内 `cd /home/teemo/project/teemo_project/cpu_ai_validation/web && bash start.sh`，宿主机保留原来的 `python3 local_access.py`；访问 http://127.0.0.1:8080。默认免网页登录、只绑定回环；SUT sudo 与 OH API key 仍按实际填写。CPU_PYTHON、OH_AUTOMATION_URL 可用环境变量调整，默认沿用现有部署。

填写供应商文件版本和独立预期配置，连接参数与授权按实际填写；原配置预填值只是编辑起点，不是自动确认。点击保存并开始探测。01/00 完成后按当前证据自动比较。已知不一致 FAIL，未知或证据无效 INCONCLUSIVE，停止后续测试。通过则等待人工审批。完整验收必须有正式最大延迟阈值以及 CPU/KVM 和 I/O 负载明确授权，否则阻止审批；放弃当前流程并补全后重新探测。审批后重新采集 01/00（V2 会话要求），再次比较，再顺序执行 02—08。08 为本地固定引擎 3600 秒，须保持控制服务存活；不要重启容器。任何 WARN/FAIL/INCONCLUSIVE 停止后续正式测试，已有批准会话时尝试 09 汇总。即使报告生成成功，验收结论仍由客观结果决定。远程请求不明时人工在 Canvas 核实后才可解除，不自动重试。不要同时执行旧总流程或手动任务。

## 报告
逐阶段预期/实际/测试方法/用例、原始执行记录、证据清单与 SHA256、证据在线浏览和下载、ZIP、历史流程、打印为 PDF。CPU05 调度采样计数、CPU06 设备 IRQ 增量/速率、CPU07 基线/宿主机/KVM/联合负载四组、CPU08 累计真实采样趋势。没有采样就不画曲线；累计最大值不是时间窗口最大值；短测与长测时长不同。原始证据为引擎已归档的脱敏输出；SHA256 不是数字签名。单文件在线查看上限 8 MB，单阶段 ZIP 上限 100 MB。

OpenHands 模式下通过已审核的 Automation 派发；CPU10/11/12 独立分析（11 仅失败时），引用限制为本次封存文件，客观结论不依赖模型输出。Agent 的工具调用约束是提示词和提交接口验证，不是操作系统级沙箱，只用于可信私有部署；不要向不受信任的 Agent 开放生产密钥。固定 Python 模式可离线验证流程，不调用 Agent。

## 验证边界
测试引擎 14 项、Web/流程 33 项离线测试通过。包括使用模拟执行器和真实文件哈希的完整顺序、停止、审批、证据、引用测试。未连接真实 SUT/Canvas，未运行真实压力或 60 分钟长测；现有 OpenHands API 协议及 Automation 导入需现场联调。CPU07 timeout 调整为 1800s，短测时长仍受估算限制。IOThread 独立绑定未实现，RT 内核为固定验收要求；暂不支持其他隔离机制。免密码服务只允许本机访问。现有政策 WARN 在新版严格门禁下会停止，需根据供应商正式标准复核，不擅自降低要求。
