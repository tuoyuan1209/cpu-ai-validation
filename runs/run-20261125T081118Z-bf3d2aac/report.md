# CPU-04 实际线程亲和性验证

Run: run-20261125T081118Z-bf3d2aac

Overall: PASS

- AFF01 显式CPU绑定与运行采样: PASS — expected=CPU 6; 100次采样; actual=允许=[6]; 实际=[6]; 样本=100
- AFF02 显式CPU绑定与运行采样: PASS — expected=CPU 0; 100次采样; actual=允许=[0]; 实际=[0]; 样本=100
- AFF03 KVM vCPU实际线程亲和性: PASS — expected={0: [0], 1: [1], 2: [2], 3: [3]}; actual={0: [0], 1: [1], 2: [2], 3: [3]}
- AFF04 QEMU非vCPU线程亲和性: PASS — expected=非vCPU线程允许范围属于[0, 1, 2, 3]; actual=线程数=11; 超范围={}
- AFF05 QEMU线程运行快照: PASS — expected=成功采集PSR快照; actual=已采集（仅最近运行CPU，不证明持续绑定）

短时采样与实际线程允许掩码验证，不代表持续运行、调度隔离或延迟达标。
