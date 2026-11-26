# V2.0 离线验证记录

输入来源：用户提供的 `cpu_ai_validation.tar.gz` 和 `openhands-automations.tar.gz` 中的实际脚本及已保存的 Automation 模板。测试代码原有 CPU01、CPU03–06、Discovery/Preflight 实现为基础；公共策略、VM解析、统一运行会话、审批、CPU07/08、CPU09 为新增或修改。旧部署逻辑没有在供应商机器上执行。

实际已通过的本地检查：

- Python 主脚本 `compileall`，包括 Automation 模板 main.py 和 hook；shell 文件 `bash -n`。
- `python -m unittest discover -s tests -v`：14项通过，包括原CPU拓扑、非连续CPU、错误绑定、缺失guest用户、禁止未经授权负载、CPU列表、Secret碰撞、停机VM不启动、MAC匹配agent地址、证据篡改、状态聚合、cyclictest解析、远程嵌入Python编译、模拟SSH的CPU00完整采集。
- 模拟现有Git仓库的安装器验证：config.yaml、runs、logs保持不变；旧脚本备份；自动修复/启动授权关闭；现有4 vCPU绑定及guest_user迁移成功。
- Automation升级包：11组 YAML/Prompt/portable JSON一致性检查；模拟本地安装目录包含11个任务定义及11个JSON文件。

这些验证仅为本地静态检查、单元测试与模拟测试，不是实际被测机的验收结果。新CPU07/08负载及cyclictest实际输出、完整01–09流程、Canvas导入及Git Sync双向同步尚未在用户设备上联调。初次应先跑01/00和02，查看证据，再逐个运行。验收阈值、实时CPU选择与负载授权由用户核对供应商标准后明确填写。
