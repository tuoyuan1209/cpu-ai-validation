# CPU Validation Web V3.2.2

适用于已经安装 V3.2.1 的现有 CPU 验收工程。仅变更网页控制器、前端、流程说明、新增离线测试和本说明。不会覆盖 start.sh、server.py、scripts、common、连接配置、供应商策略或历史证据。无需更新 OpenHands 自动化任务。

## 安装
在宿主机项目共享目录放置压缩包，进入 Docker 容器，确认没有正在执行、排队或未协调的测试任务，停止旧网页服务，然后：

```
cd /home/teemo/project/teemo_project
mkdir -p v322_upgrade
tar -xzf cpu_ai_validation_v322_patch.tar.gz -C v322_upgrade
python3 v322_upgrade/install_v322.py --target cpu_ai_validation
python3 v322_upgrade/install_v322.py --target cpu_ai_validation --apply
```
保留 BACKUP 路径。重新执行 `cd cpu_ai_validation/web && bash start.sh`，正确输入被测机 sudo 密码（不写入文件）。强制刷新网页。因控制器代码已变化，必须创建新验收流程，重新确认供应商规格和测试授权；不能复用旧批准会话直接续跑。

## 规则
- CPU-03 必须具有本次会话有效回执及完整封存证据，恰有 ISO01–ISO13 共13项，且仅 ISO10 为 WARN、其余为 PASS，才允许继续。实际 IRQ 仍由 CPU-06 动态实验检查。其他 WARN、证据异常及非阈值缺失的 INCONCLUSIVE 均停止；FAIL 始终停止。
- CPU-03 原 WARN 不改变。若所有阶段完成并有正确 CPU-09 汇总，含未解决 WARN 的最终判定为 INCONCLUSIVE；无阈值完整测量也为 INCONCLUSIVE。CPU-06 通过不消除静态警告。不能宣称所有验收通过。
- 报告首页分别统计 PASS/WARN/FAIL/INCONCLUSIVE/未执行（不含汇总 CPU-09），列出异常用例、预期、实测、判定依据及原始 JSON 链接；下方保留详细用例、原始文件和证据 ZIP。进度页展示已分流警告。审批状态提示更新。
- 在 OpenHands 模式下，归档存在 WARN 时不再跳过 CPU-11，即使测量全部完成也会尝试派发。仍依赖现有三个分析任务及 API 可用性；固定 Python 模式不调用 Agent。未新增暂停点续跑功能；未知 WARN 停止后需要复核并重新开始。

## 回滚
停止任务及网页后，运行 `python3 v322_upgrade/install_v322.py --target cpu_ai_validation --rollback '实际BACKUP路径'`。安装器拒绝覆盖不匹配的本地代码；回滚拒绝覆盖安装后另行修改的文件。

## 验证范围
实际运行网页/工作流离线测试 68 项、底层 test_offline.py 13 项，均通过。全量底层测试首次运行超时，未取得 discovery mock 用例的本次通过记录。无真实 SUT、Canvas 或浏览器联调，本包不改变底层测试脚本或远程配置。
