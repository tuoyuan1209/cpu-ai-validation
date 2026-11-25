# CPU-05 普通任务调度隔离验证

Run: run-20261125T083518Z-521cf4d8

Overall: INCONCLUSIVE

- SCH01 实际调度采样: INCONCLUSIVE — expected=1 workers; 3s; actual=incomplete sample or insufficient affinity coverage
- SCH02 实际调度采样: INCONCLUSIVE — expected=8 workers; 5s; actual=incomplete sample or insufficient affinity coverage
- SCH03 实际调度采样: INCONCLUSIVE — expected=8 workers; 10s; actual=incomplete sample or insufficient affinity coverage
- SCH04 隔离核心侵入统计: INCONCLUSIVE — expected=0次采样; actual=0次；有效阶段=0/3
- SCH05 显式绑定对照: PASS — expected=CPU [6]; 1 workers; 3s; actual=counts={6: 299}; allowed=[[6]]; cpu_seconds=0.00
- SCH06 KVM负载下普通任务调度: INCONCLUSIVE — expected=有效并发负载证据; actual=guest workload or host sampling failed; inspect stdout/stderr

有限采样仅覆盖本次测试任务，不证明系统所有线程无侵入；不代表实时延迟达标。
