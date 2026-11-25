# CPU-03 核心隔离配置验证

Run: run-20261125T075440Z-e5221249

Overall: WARN

- ISO01 实时内核: PASS — expected=1; actual=1
- ISO02 在线CPU: PASS — expected=0-7; actual=0-7
- ISO03 isolcpus启动参数（domain）: PASS — expected=4-7; actual=4-7
- ISO04 实际隔离CPU: PASS — expected=4-7; actual=4-7
- ISO05 NOHZ_FULL: PASS — expected=4-7; actual=4-7
- ISO06 RCU卸载启动配置: PASS — expected=4-7; actual=4-7
- ISO07 默认IRQ亲和性（运行时）: PASS — expected=f; actual=0f
- ISO08 内核线程启动参数: PASS — expected=0; actual=0
- ISO09 全局workqueue亲和性: PASS — expected=不覆盖隔离CPU; actual=掩码=0f; 交集=[]
- ISO10 实际IRQ亲和性: WARN — expected=无IRQ有效亲和性覆盖隔离CPU; actual=采集66项; 涉及隔离CPU的IRQ: 153, 154, 155, 156, 174, 175, 176, 177
- ISO11 实时测试核心: PASS — expected=CPU 6 在线且隔离; actual=在线=0-7; 隔离=4-7
- ISO12 KVM vCPU绑定: PASS — expected={0: {0}, 1: {1}, 2: {2}, 3: {3}}; actual=持久+运行配置: [{0: {0}, 1: {1}, 2: {2}, 3: {3}}, {0: {0}, 1: {1}, 2: {2}, 3: {3}}]
- ISO13 KVM模拟器绑定: PASS — expected=0-3; actual=持久+运行配置: [{0, 1, 2, 3}, {0, 1, 2, 3}]

仅验证配置与快照，不代表实际调度、中断或延迟达标。
