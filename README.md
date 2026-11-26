# CPU AI Validation V2.0 — KVM供应商交付验收

升级对象：既有 `cpu_ai_validation` 仓库（tuoyuan1209/cpu-ai-validation）。执行模式：供应商配置完成后独立验证，不自动修复、不修改隔离配置、不自动启动虚拟机。实际测试会产生临时进程、短时CPU负载，以及经授权的临时文件I/O；与纯只读探测不同。保留旧 Git 历史和 runs/。旧 `provision_all.py` 默认阻止执行，原部署逻辑仅为兼容留存（明确 deploy 模式+显式参数才能执行，未在新硬件适配）。

## 安装（在 OpenHands Docker 容器内）

先停用旧 Automation，确认没有正在运行的旧任务。压缩包解压到独立目录，不直接解压覆盖原仓库。使用现有共享 Python（或设置为安装 PyYAML 的 Python）：

```bash
PY=/root/.cache/uv/archive-v0/OvJCewHopHDXy8xF/bin/python
$PY install_upgrade.py             # dry run
$PY install_upgrade.py --apply    # 本地覆盖相关文件，先备份到目标 .validation/backups/
cd /home/teemo/project/teemo_project/cpu_ai_validation
$PY -m unittest discover -s tests -v
```

安装器保留 config.yaml、.git、logs/、runs/；现有 isolation_policy.yaml 核心值保留并补充必要字段，压力及I/O授权强制置 false；provision_policy.yaml 所有已知自动修复/启动开关置 false。目标仓库之外没有远程操作或推送。注意旧备份里可能有敏感信息，切勿提交或上传。

## 首次使用 / 更换供应商配置

1. 保留现有 SSH 配置、known_hosts、Secret。若目标地址或系统变更，先核实SSH主机指纹。用 Canvas 的 CPU-01 / CPU-00，或在容器里运行：

```bash
# 手动注入 sudo secret，避免终端历史；NOPASSWD 环境可不设置。
read -rsp 'SUT sudo password: ' SUT_SUDO_PASSWORD; echo; export SUT_SUDO_PASSWORD
PY=/root/.cache/uv/archive-v0/OvJCewHopHDXy8xF/bin/python
$PY scripts/run_stage.py 01
$PY scripts/run_stage.py 00
```

2. 查看 CPU-00 返回的具体 `runs/discovery-...` 目录中的 `report.md`, `vm_config.json`, `isolation_policy.detected.yaml`, `observed.json`。探测候选配置不能直接作为验收标准；人工核对供应商协议。候选 test_cpu / guest_user / max_latency_us 故意为空；`[REDACTED]` 内容也不能直接使用。参照 `isolation_policy.example.yaml` 补充正式 `isolation_policy.yaml`：所有CPU集合、每个vCPU映射、emulator、guest_user、指定 test_cpu、负载授权和延迟阈值。若有多网卡，指定 guest_mac；guest_ip 可用于消除多地址歧义，但必须匹配 lease/agent 观测。虚拟机由供应商事先启动，guest SSH trust 与测试权限须由供应商确认。
3. 人工确认后批准一次：

```bash
$PY scripts/run_stage.py approve --reviewed
```

会记录新会话、代码及配置SHA256、目标环境指纹（machine-id/boot_id、kernel/cmdline、CPU集合、PID1/workqueue/default IRQ、选定VM持久及live XML绑定、IRQ有效亲和性）。不将实际探测结果自动提升为承诺指标。配置、代码或目标指纹改变必须重新探测、批准和测试，不混合历史会话。指纹不是对所有运行时线程变化的绝对证明。

4. 逐项运行（批准后重跑00、01用于同一会话报告）：

```bash
$PY scripts/run_stage.py 01
$PY scripts/run_stage.py 00
$PY scripts/run_stage.py 02
$PY scripts/run_stage.py 03
$PY scripts/run_stage.py 04
$PY scripts/run_stage.py 05
$PY scripts/run_stage.py 06
$PY scripts/run_stage.py 07
# 必须在独立持久控制终端，不能放进1800秒的Automation
$PY scripts/run_stage.py 08 --allow-long
$PY scripts/run_stage.py 09
unset SUT_SUDO_PASSWORD
```

也可运行 `bash run_all.sh discovery`（未批准的环境探测）；批准后 `bash run_all.sh verify`（01、00、02–07、09，缺08不会显示整体验收PASS）；`bash run_all.sh full`（包含连续08，使用持久终端）。流程遇 FAIL/INCONCLUSIVE 停止并输出部分报告；03允许WARN继续。如果06因严格设备IRQ增量失败，独立运行07/08可以继续收集性能证据，但09必须保留FAIL。模型无需判断/修改配置。单阶段使用 `run_stage.py`，不要直接执行各原子脚本绕过批准、会话与依赖校验。

## 测试项目

| 阶段 | 功能 |
|---|---|
| 00 | SSH、CPU、内核、隔离、IRQ、cgroup、NVMe、KVM与候选策略探测 |
| 01 | SSH身份及sudo权限检查 |
| 02 | 只读预检，检查运行中的测试VM与工具 |
| 03 | isolcpus-domain、RT、NOHZ、RCU、IRQ、workqueue、KVM持久和live绑定 |
| 04 | 实际vCPU及非vCPU线程亲和性、普通和隔离核显式绑定采样 |
| 05 | 默认及扩大亲和性的调度采样、KVM并发压力；worker动态配置 |
| 06 | 60秒基线、宿主CPU/Guest CPU/网络磁盘负载下IRQ增量及NVMe统计 |
| 07 | cyclictest基线、宿主压力、Guest压力；可选所有隔离核基线对比 |
| 08 | 3600秒连续cyclictest + Guest stress-ng，检查负载重叠、周期数和FIFO线程绑定 |
| 09 | 同一审批会话内逐阶段验证 SHA256SUMS 并汇总 |

`realtime.max_latency_us` 由供应商承诺确认；为空时仍采集实际数据但状态为INCONCLUSIVE。07/08要求测试用户可执行FIFO调度及memlock，不自动授予权限。Guest busy 计算排除 steal，不把被抢占时间冒充有效CPU负载。60秒/60分钟单线程1ms周期为现有约定，可按批准配置修改短测时间/优先级/周期；长测固定3600秒。08长测不会拆段或在 OpenHands 中启动；执行前确认供应商允许持续满载。可在另一终端 `tail -F logs/live.log` 观察阶段开始/完成；长阶段内部stdout/stderr在远程命令完成后落盘，当前实现没有秒级流式cyclictest日志，进程受远程超时和负载程序自身时限约束。中断风险仍按原标准保留，数字IRQ非零为FAIL，配置覆盖为WARN；有限采样不等于证明无任何干扰。

## 适用范围与尚未验证的点

- 支持 Linux host PREEMPT_RT + `isolcpus` domain + libvirt system KVM，RT线程在宿主隔离核心，VM负载在 housekeeping 集合。支持非连续 CPU ID 和不同vCPU数量。
- 不声称支持 cpuset-only、Guest-RT、非libvirt、热插拔/非连续vCPU ID、独立IOThread绑定等不同部署；这些情况应先探测并单独设计策略，拒绝误判。桥接VM可使用 MAC匹配的 guest-agent 地址；无 lease/agent 或密钥/known_hosts 不可用时证据不足，不猜IP。
- 默认不允许压力或I/O；必须明确授权。测试采样并非完整内核调度跟踪。SHA256是完整性校验，不是第三方签名或防恶意篡改机制。
- 复用已有阶段实现，统一了策略、guest连接及运行/审批；部分原有SSH/证据收集函数保留以兼容已有脚本，不是全部重写。新07/08及所有改造尚未在真实SUT上集成验证。参见 VALIDATION.md。

## Git管理

检查 `git status` 和 `git diff`，建议单独重构分支提交。安装器追加忽略规则，不删除或取消跟踪既有历史。已经tracked的日志/运行目录可在备份后自行执行 `git rm -r --cached --ignore-unmatch logs runs`（不删除本地文件）；这不会从过去的Git提交清除敏感信息。请审查原历史、私有仓库权限及是否有曾泄露的Secret，必要时轮换。不要 `git add .` 直接提交未审查文件；配置及原始证据按公司制度单独保存。
