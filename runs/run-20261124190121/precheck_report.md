# CPU 核心隔离测试 — 环境预检查报告（Stage 0）

## 运行信息

| 项目 | 值 |
|---|---|
| 运行编号 (run_id) | run-20261124190121 |
| 运行模式 (mode) | precheck（仅执行 Stage 0 环境预检查） |
| 执行时间 | 2026-11-24 19:01–19:03 (CST) |
| 执行位置 | OpenHands 部署服务器（本地检查 1–3）；检查 4–6 需通过 SSH 在被测机执行 |
| 被测机 (host) | 192.168.41.10 |
| SSH 用户 / 端口 | test / 22 |
| SSH 密钥（配置值） | ~/.ssh/cpu_test_ed25519（展开后：/root/.ssh/cpu_test_ed25519） |
| 配置文件 | /home/teemo/project/teemo_project/cpu_ai_validation/config.yaml |

**说明**：config.yaml 中 mode 字段为 `precheck`，按该模式执行。本次运行未使用容器/Agent 环境自身数据替代任何被测机测试数据（precheck 模式不执行任何测试）。

## 预检查总体结论：❌ 未通过（检查项 3 失败，按全局规则立即终止后续检查与测试）

| # | 检查项 | 结果 |
|---|---|---|
| 1 | 配置文件 | ✅ 通过 |
| 2 | 工作目录 | ✅ 通过 |
| 3 | SSH 密钥 | ❌ **失败** |
| 4 | SSH 连接状态 | ⛔ 未执行（因检查 3 失败终止） |
| 5 | 远程测试工具 | ⛔ 未执行（因检查 3 失败终止） |
| 6 | 实时调度权限 | ⛔ 未执行（因检查 3 失败终止） |

---

## 逐项检查详情

### 检查 1：配置文件 ✅ 通过

- **实际命令**：
  ```
  CFG=/home/teemo/project/teemo_project/cpu_ai_validation/config.yaml
  [ -f "$CFG" ] && [ -r "$CFG" ]
  grep -qE "^<key>:" "$CFG"   # key ∈ {host, ssh_user, ssh_port, ssh_key, mode}
  ```
- **输出**：
  ```
  文件存在且可读
  key host: 存在        (host: "192.168.41.10")
  key ssh_user: 存在    (ssh_user: "test")
  key ssh_port: 存在    (ssh_port: 22)
  key ssh_key: 存在     (ssh_key: "~/.ssh/cpu_test_ed25519")
  key mode: 存在        (mode: "precheck")
  ```
- **结论**：配置文件存在、可读，5 个必填键齐全；mode 为合法值 `precheck`。

### 检查 2：工作目录 ✅ 通过

- **实际命令**：
  ```
  cd /home/teemo/project/teemo_project/cpu_ai_validation
  echo "test" > runs/run-20261124190121/.write_test_<pid>   # 写入→读回→删除
  echo "test" > runs/run-20261124190121/results/.write_test_<pid>
  ```
- **输出**：
  ```
  工作目录写入测试: PASS (已写入并删除测试文件)
  runs/run-20261124190121/results/ 写入测试: PASS
  ```
- **结论**：工作目录与本次运行目录 `runs/run-20261124190121/`、`results/` 子目录均存在且可读写（已实际写入并删除测试文件验证）。

### 检查 3：SSH 密钥 ❌ 失败

- **实际命令**：
  ```
  KEY=/root/.ssh/cpu_test_ed25519        # "~/.ssh/cpu_test_ed25519" 按运行用户 home 展开
  [ -f "$KEY" ] && [ -r "$KEY" ]
  find /home /root -maxdepth 4 -name "cpu_test_ed25519*"   # 辅助排查其他家目录
  ```
- **输出**：
  ```
  密钥文件不存在或不可读
  find 未在任何位置发现名为 cpu_test_ed25519* 的文件
  /root/.ssh/ 目录权限正常 (700, root)，其中仅存在:
    id_ed25519 / id_ed25519.pub（通用密钥，非配置指定的密钥名）
  /home/teemo/.ssh/ 不存在
  ```
- **失败原因**：config.yaml 指定的密钥文件 `~/.ssh/cpu_test_ed25519`（展开为 `/root/.ssh/cpu_test_ed25519`）在 OpenHands 服务器上**不存在**。已搜索 `/home` 与 `/root` 下所有家目录，均无该密钥文件。
- **影响**：无法按统一 SSH 参数（`-i <ssh_key> -p 22 -o BatchMode=yes -o ConnectTimeout=10 test@192.168.41.10`）建立非交互连接，检查 4–6 无法执行。
- **修复建议**（任选其一后重新运行本自动化，mode 改为 `full`/`longtime` 执行完整测试）：
  1. 将正确的 ed25519 测试密钥放置到 `/root/.ssh/cpu_test_ed25519` 并设置权限：
     ```
     chmod 600 /root/.ssh/cpu_test_ed25519
     ```
     并确保该公钥已配置到被测机 192.168.41.10 的 `test` 用户 `~/.ssh/authorized_keys` 中（公钥可提前部署，公钥非机密）。
  2. 或修改 config.yaml 的 `ssh_key` 为服务器上实际存在的密钥路径（例如现有的 `~/.ssh/id_ed25519`，前提是它已被授权登录被测机 test 用户）。
  3. 密钥放置完成后，重新运行本自动化；检查 4 将验证 BatchMode 非交互登录是否真正可用。

### 检查 4：SSH 连接状态 ⛔ 未执行

- **原因**：检查 3 失败（密钥文件不存在），按全局规则第 1 条“前序阶段失败立即终止后续阶段”终止。
- **计划命令**（未执行）：
  ```
  ssh -i /root/.ssh/cpu_test_ed25519 -p 22 -o BatchMode=yes -o ConnectTimeout=10 test@192.168.41.10 hostname
  ```

### 检查 5：远程测试工具 ⛔ 未执行

- **原因**：同检查 4，依赖 SSH 连接。
- **计划命令**（未执行）：`command -v cyclictest stress-ng taskset mpstat`（远程执行）

### 检查 6：实时调度权限 ⛔ 未执行

- **原因**：同检查 4，依赖 SSH 连接。
- **计划命令**（未执行）：远程以 `sudo -n` 非交互方式验证 test 用户具备 SCHED_FIFO 优先级 80 权限。

---

## 终止说明与后续步骤

1. 本次 precheck **未通过**，未执行任何 CPU 核心隔离测试，未产生任何被测机测试数据（未执行阶段均如实标记，无任何估算或虚构数据）。
2. 红线合规：未修改被测机 GRUB/内核参数，未重启被测机，未在任何输出中打印私钥内容。
3. 阻断项唯一且明确：**缺少 SSH 密钥文件 `/root/.ssh/cpu_test_ed25519`**。
4. 修复密钥问题后，重新运行本自动化即可从 Stage 0 完整重走全部检查；如需完整测试，将 config.yaml 的 `mode` 设为 `full` 或 `longtime`。

## 附录：本次运行交付物清单

```
/home/teemo/project/teemo_project/cpu_ai_validation/runs/run-20261124190121/
└── precheck_report.md   （本文件）
```