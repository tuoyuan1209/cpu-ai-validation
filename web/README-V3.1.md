# CPU Validation Center V3.1 — 供应商规格与自动比对

此升级覆盖 `cpu_ai_validation/web/` 中的网页、后端及测试文件，不替换 V2 测试引擎、OpenHands Automation、start.sh、local_access.py、已有 `.web-state/` 或历史证据。

## 安装（已安装 V3.0 免密码补丁的环境）

1. 在官方 Canvas 和网页确认没有运行中的任务。停止网页服务（启动终端 Ctrl+C），本机转发服务可继续运行。
2. 容器内备份原网页源码后，从 `/home/teemo/project/teemo_project` 执行：
   ```bash
   tar -xzf web_v31_supplier_patch.tar.gz -C cpu_ai_validation
   cd cpu_ai_validation/web
   bash start.sh
   ```
3. 宿主机如尚未启动转发，执行 `python3 local_access.py`（位于同一 web 目录）。访问 http://127.0.0.1:8080，Ctrl+Shift+R 强制刷新。
4. 免密码仍只允许本机回环访问；SUT sudo 和 OpenHands API 认证仍按原方式注入。不要向局域网/公网开放。

## 操作

- 供应商规格：填写真实交付文档的版本/编号及预期值。初始填充值来自现有正式策略，**不是供应商文件，也不是自动采集值**。确认来源后保存。被测地址、SSH 用户及端口可单独保存，原密钥及其他配置字段保留；修改目标后重新执行 CPU-01、CPU-00。
- 验收配置与审批：自动校验最近一次 CPU-00 PASS 的 SHA256SUMS，并比较当前目标与探测目标；较新的失败/未完成探测或连接变更会要求重新探测。CPU 列表按集合比较；空 IOThread 映射的 [] 与 {} 等价。若 VM 正在运行且有对应记录，追加 live XML 字段对比。不能用持久 XML 证明运行线程行为，后续 CPU-04 等仍必须执行。
- 自动比对仅覆盖探测已支持的静态配置（在线/隔离/普通核心、内核线程配置、隔离机制、RT 内核、KVM 名称/数量/绑定）。普通核心是在线减隔离的推导，非调度运行证据。Guest 登录用户/地址、实时测试核心、压力授权、性能阈值是人工确认项。延迟阈值留空时不能证明性能达标。
- 一致、差异、无法确认三类结果。任一差异/未知或证据校验失败时网页拒绝审批，须核对独立供应商规格或整改并重新探测；不得用实际值覆盖预期值来取得通过。网页可直接启动后续验证，报告仍可查看。保存新规格会撤销 active.json 指针，历史会话和报告保留。新规格版本记录在 `.web-state/supplier-versions/`，当前版本在 `.web-state/supplier.json`；该目录应留在本机、不要上传 Git。未实现版本回滚 UI。
- 人工审批：两项确认后调用现有 `approve --reviewed`。必须等待固定脚本成功建立会话，不能把网页请求成功当作批准成功。新版本要求在网页保存一次真实规格；旧 CLI 入口仍存在，网页不能限制管理员在官方 Canvas 或终端直接执行命令。V2 执行时仍校验目标指纹。
- 任务执行：原有 OpenHands 调用入口、固定 Python 入口、长测和日志/报告保留。不要并发从多个界面触发。60 分钟长测仍由本地持久后台进程执行。

## 现有引擎限制

仅支持宿主 RT + isolcpus-domain + KVM vCPU 在普通核心区；非空 IOThread 独立绑定暂不支持；连续长测固定 3600 秒。阈值由真实供应商验收标准指定。本升级未修改这些引擎限制，也未连接真实被测机或 OpenHands 服务。

## 离线验证

从安装后的 web 目录运行（需要原有 V2 引擎和 PyYAML）：
```bash
PY=/root/.cache/uv/archive-v0/OvJCewHopHDXy8xF/bin/python
"$PY" -m unittest discover -s tests -v
```
本包 25 项测试通过，包括真实 V2 策略校验和证据清单校验的本地模拟；JavaScript 语法通过。真实目标机及 Canvas 联调仍需进行。
