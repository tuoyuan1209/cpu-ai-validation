# CPU 核心隔离测试 — 环境预检查报告（Stage 0）

## 运行信息

| 项目 | 值 |
|---|---|
| 运行编号 (run_id) | run-20261125101622 |
| 运行模式 (mode) | precheck（仅执行 Stage 0 环境预检查，来自 config.yaml） |
| 执行时间 | 2026-11-25 10:16–10:20 (CST) |
| 执行位置 | OpenHands 部署服务器（本地检查 1–3）；检查 4–6 通过 SSH 在被测机执行 |
| 被测机 (host) | 192.168.41.10（远程 hostname：test-SBCPTLCX3R100） |
| SSH 用户 / 端口 | test / 22 |
| SSH 密钥（配置值） | /root/.ssh/id_ed25519（绝对路径，无 ~ 展开问题；权限 600） |
| 配置文件 | /home/teemo/project/teemo_project/cpu_ai_validation/config.yaml |

**说明**：与上一轮运行 run-20261124190121 相比，config.yaml 的 `ssh_key` 已由不存在的 `~/.ssh/cpu_test_ed25519` 改为实际存在的 `/root/.ssh/id_ed25519`，检查 3 本轮通过。mode 仍为 `precheck`，本次运行未执行任何压力/延迟测试，未产生任何被测机测试数据。

## 预检查总体结论：❌ 未通过（检查项 6 失败，按全局规则立即终止，未执行任何后续测试）

| # | 检查项 | 结果 |
|---|---|---|
| 1 | 配置文件 | ✅ 通过 |
| 2 | 工作目录 | ✅ 通过 |
| 3 | SSH 密钥 | ✅ 通过 |
| 4 | SSH 连接状态 | ✅ 通过 |
| 5 | 远程测试工具 | ✅ 通过 |
| 6 | 实时调度权限 | ❌ **失败** |

---

## 逐项检查详情

### 检查 1：配置文件 ✅ 通过

- **实际命令**：
  ```
  CFG=/home/teemo/project/teemo_project/cpu_ai_validation/config.yaml
  [ -f "$CFG" ] && [ -r "$CFG" ];  grep -E "^<key>:" "$CFG"   # key ∈ {host, ssh_user, ssh_port, ssh_key, mode}
  ```
- **输出**：
  ```
  PASS: 文件存在且可读
  key host:     host: "192.168.41.10"
  key ssh_user: ssh_user: "test"
  key ssh_port: ssh_port: 22
  key ssh_key:  ssh_key: "/root/.ssh/id_ed25519"
  key mode:     mode: "precheck"
  ```
- **结论**：文件存在、可读，5 个必填键齐全；mode 为合法值 `precheck`。

### 检查 2：工作目录 ✅ 通过

- **实际命令**：
  ```
  cd /home/teemo/project/teemo_project/cpu_ai_validation
  echo "test" > runs/run-20261125101622/.write_test_<pid>      # 写入→读回→删除
  echo "test" > runs/run-20261125101622/results/.write_test_<pid>
  ```
- **输出**：
  ```
  PASS: 工作目录写入测试（已写入并删除）
  PASS: runs/run-20261125101622/results/ 写入测试（已写入并删除）
  ```
- **结论**：工作目录、本次运行目录及 `results/` 子目录均存在且可读写（实际写入/读回/删除验证通过）。

### 检查 3：SSH 密钥 ✅ 通过

- **实际命令**：
  ```
  KEY="/root/.ssh/id_ed25519"
  [ -f "$KEY" ] && [ -r "$KEY" ];  stat -c 'perm=%a' "$KEY"
  ```
- **输出**：
  ```
  PASS: 密钥文件存在且可读
  权限: 600
  权限检查: 正常
  ```
- **结论**：config.yaml 指定的密钥文件存在、可读，权限 600 正常。未在任何输出中包含密钥内容。

### 检查 4：SSH 连接状态 ✅ 通过

- **实际命令**：
  ```
  ssh -i /root/.ssh/id_ed25519 -p 22 -o BatchMode=yes -o ConnectTimeout=10 \
      -o StrictHostKeyChecking=accept-new test@192.168.41.10 hostname
  ```
- **输出**：
  ```
  test-SBCPTLCX3R100     (退出码 0)
  ```
- **结论**：BatchMode 非交互登录成功，远程命令执行正常。
- 备注：`StrictHostKeyChecking=accept-new` 为首次连接的 host key 自动接受（known_hosts 已有该主机记录，后续连接不再写入）。

### 检查 5：远程测试工具 ✅ 通过

- **实际命令**（远程执行）：
  ```
  for t in cyclictest stress-ng taskset mpstat; do command -v $t; done
  ```
- **输出**：
  ```
  PASS: cyclictest -> /usr/local/bin/cyclictest
  PASS: stress-ng  -> /usr/bin/stress-ng
  PASS: taskset    -> /usr/bin/taskset
  PASS: mpstat     -> /usr/bin/mpstat
  ```
- **结论**：4 个必需工具全部可用（cyclictest 位于 /usr/local/bin，为手工安装版本）。

### 检查 6：实时调度权限 ❌ 失败

- **验证目标**：ssh_user（test）能否以 SCHED_FIFO 优先级 80 运行实时进程（cyclictest 必需）；权限检查使用 `sudo -n`，无交互等待。
- **实际命令**（远程执行）：
  ```
  whoami
  sudo -n true
  ulimit -r
  chrt -f 80 sleep 0.2
  id test
  grep ^Cap /proc/self/status
  grep rtprio /etc/security/limits.conf /etc/security/limits.d/*.conf
  ```
- **输出**：
  ```
  whoami=test
  SUDO_N: 不可用 (sudo -n 失败 —— 该用户 sudo 需要密码，非交互下不可用)
  RLIMIT_RTPRIO (ulimit -r): 0
  chrt: failed to set pid 0's policy: Operation not permitted    (chrt -f 80 退出码 1)
  id: uid=1000(test) gid=1000(test) groups=...,27(sudo),...
  CapEff: 0000000000000000   (无 CAP_SYS_NICE)
  /etc/security/limits.conf: 无 rtprio 条目（仅 pipewire 组有 rtprio 95）
  ```
- **失败原因**：
  1. test 用户会话 `RLIMIT_RTPRIO=0` —— PAM limits 中未配置其 `rtprio` 上限，普通用户无法设置任何实时优先级；
  2. `chrt -f 80`（对子进程设置 SCHED_FIFO 优先级 80）被内核拒绝：`Operation not permitted`；
  3. test 用户在 `sudo` 组但 `sudo -n` 失败（需要密码）——按全局规则“sudo -n 失败即记为权限不足”，不可用于提权；
  4. 无 CAP_SYS_NICE 能力，无法绕过 RLIMIT_RTPRIO。
  综合结论：test 用户**不具备** SCHED_FIFO 优先级 80 的实时调度权限。
- **过程备注**：首次验证脚本中 python3 `sched` 模块调用方式有误（`AttributeError: module 'sched' has no attribute 'SCHED_FIFO'`），已改用 `chrt -f 80 sleep 0.2` 标准方式复测，结论一致：RT_SET: FAIL。
- **进程清理验证**：验证子进程（chrt/sleep）已全部退出；`pgrep cyclictest`、`pgrep stress-ng` 均无结果。pgrep -f 匹配到的唯一条目是验证命令自身的 shell（字符串自匹配假阳性），无真实测试进程残留。
- **修复建议**（在被测机 192.168.41.10 上以 root 执行，任选方案 A 或 B 后重新运行本自动化）：
  - **方案 A（推荐，改动最小）**：为 test 用户放开 rtprio 上限：
    ```
    cat > /etc/security/limits.d/90-cpu-rt.conf <<'EOF'
    test - rtprio 99
    test - memlock unlimited
    EOF
    ```
    使 test 用户重新登录（新 SSH 会话生效后 `ulimit -r` 应 ≥ 80）即可直接以 SCHED_FIFO 80 运行 cyclictest，无需 sudo。
  - **方案 B**：为 test 用户配置 NOPASSWD 的受限 sudo，例如在 `/etc/sudoers.d/cpu-rt` 中授予 `chrt`/`cyclictest`/`stress-ng`/`taskset`/`mpstat` 的 NOPASSWD 权限（自动化脚本中已按规则统一使用 `sudo -n`）：
    ```
    test ALL=(root) NOPASSWD: /usr/local/bin/cyclictest, /usr/bin/stress-ng, /usr/bin/taskset, /usr/bin/mpstat, /usr/bin/chrt
    ```
  - 说明：以上均为被测试机用户权限/limits 配置，不涉及 GRUB、内核启动参数或重启（红线合规）。修复后重新运行本自动化，检查 6 将复验 `chrt -f 80`。

---

## 终止说明与后续步骤

1. 本次 precheck **未通过**，阻断项：检查 6（实时调度权限）。未执行 Stage 1–5，未执行任何 CPU 隔离测试，无任何被测机测试数据（无编造/估算）。
2. 红线合规：未修改被测机 GRUB/内核参数，未重启被测机，未在任何输出中打印私钥内容（仅引用密钥路径）。
3. 与上一轮（run-20261124190121）对比：检查 3 已由失败转为通过；当前唯一剩余阻断项为 RT 权限。
4. 按上述修复建议放开 RT 权限后重新运行本自动化即可完整复验 Stage 0；全部通过后，将 config.yaml 的 `mode` 设为 `full` 或 `longtime` 执行完整隔离测试。

## 附录：本次运行交付物清单

```
/home/teemo/project/teemo_project/cpu_ai_validation/runs/run-20261125101622/
├── precheck_report.md   （本文件）
└── results/             （空，precheck 模式无测试数据回传）
```