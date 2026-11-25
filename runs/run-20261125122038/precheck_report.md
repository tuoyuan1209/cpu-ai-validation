# CPU 核心隔离测试 — 环境预检查报告（Stage 0）

## 运行信息

| 项目 | 值 |
|---|---|
| 运行编号 (run_id) | run-20261125122038 |
| 运行模式 (mode) | precheck（来自 config.yaml） |
| 执行时间 | 2026-11-25 12:20 ~ 2026-11-25 12:20:39 (本地时间) |
| 执行位置 | OpenHands 部署服务器（检查 1–4 本地执行；检查 5–7 通过 SSH 在被测机执行） |
| 被测机 (host) | 192.168.41.10（远程 hostname: ***-SBCPTLCX3R100） |
| SSH 用户 / 端口 | test / 22 |
| SSH 密钥（配置值） | /root/.ssh/id_ed25519（仅引用路径） |
| 配置文件 | /home/teemo/project/teemo_project/cpu_ai_validation/config.yaml |

**说明**：本次运行为 Stage 0 环境预检查，未执行任何 CPU 隔离测试，未使用容器/Agent 环境自身数据替代被测机数据，未修改被测系统。

## 预检查总体结论：✅ 通过（7/7）

| # | 检查项 | 结果 |
|---|---|---|
| 1 | 配置文件 | ✅ 通过 |
| 2 | 工作目录 | ✅ 通过 |
| 3 | Secret 访问验证 | ✅ 通过 |
| 4 | SSH 密钥 | ✅ 通过 |
| 5 | SSH 远程连通性 | ✅ 通过 |
| 6 | sudo 可用性 | ✅ 通过 |
| 7 | 基础工具存在性 | ✅ 通过 |

---

## 逐项检查详情

### 检查 1：配置文件 ✅

- 文件存在且可读: /home/teemo/project/teemo_project/cpu_ai_validation/config.yaml
- mode 合法: precheck
- provision 段: enabled=True install_tools=True configure_rt_permissions=True configure_device_permissions=True modify_kernel_parameters=False allow_reboot=False
- acceptance 段: {"max_latency_us": null}

### 检查 2：工作目录 ✅

- /home/teemo/project/teemo_project/cpu_ai_validation: 写入→读回→删除 验证通过
- /home/teemo/project/teemo_project/cpu_ai_validation/runs/run-20261125122038: 写入→读回→删除 验证通过
- /home/teemo/project/teemo_project/cpu_ai_validation/runs/run-20261125122038/results: 写入→读回→删除 验证通过

### 检查 3：Secret 访问验证 ✅

- SUT_SSH_PASSWORD: 可用
- SUT_SUDO_PASSWORD: 可用
- 结论: 未在任何输出中打印凭据内容（只输出可用/不可用）

### 检查 4：SSH 密钥 ✅

- 密钥路径: /root/.ssh/id_ed25519（仅引用路径，不输出内容）
- 文件存在且可读; 权限: 600
- 权限检查: 正常

### 检查 5：SSH 远程连通性 ✅

- 认证方式: key（密钥优先，失败时密码回退）
- host key 指纹(SHA256): SHA256:QBCNJTFuk9aXfZUgI59xMPwb741LlnWZbdahIVsv+mU
- host key 状态: match(与 known_hosts 一致)
- 远程 hostname: ***-SBCPTLCX3R100
- 远程内核版本: 6.17.11-intel-ese-experimental-lts-rt
- 远程登录用户: ***
- 结论: 非交互登录成功，主机身份已确认（hostname 核对 + 内核版本记录）

### 检查 6：sudo 可用性 ✅

- sudo -n: 不可用（需要密码）
- sudo 密码非交互认证（Secret 经 stdin 注入）: 可用
- 结论: 可用（密码非交互）

### 检查 7：基础工具存在性 ✅

- cyclic***: 存在 → /usr/local/bin/cyclic***
- stress-ng: 存在 → /usr/bin/stress-ng
- taskset: 存在 → /usr/bin/taskset
- mpstat: 存在 → /usr/bin/mpstat
- chrt: 存在 → /usr/bin/chrt
- 软件包管理器: apt-get

---

## Secret 可用性结论

- SUT_SSH_PASSWORD: 可用
- SUT_SUDO_PASSWORD: 可用
- 结论: 未在任何输出中打印凭据内容（只输出可用/不可用）

## 红线合规声明

- [x] 未修改被测系统：precheck 模式仅执行只读检查与权限自检（sudo -n / sudo -S true），未安装软件、未修改任何被测机配置、未调整 GRUB/内核启动参数。
- [x] 未重启/关机被测机。
- [x] 凭据保护：SSH 密码与 sudo 密码仅经 stdin 注入，未出现在命令行参数、日志、报告或本输出中；密钥仅引用路径，未输出私钥内容。
- [x] 所有远程数据（hostname、内核、工具路径、sudo 状态）均来自被测机 192.168.41.10 的实际 SSH 执行结果，无编造/估算。
- [x] 远程命令均带超时保护；检查所用子进程（无持久进程）无残留。

## 终止/后续说明

全部 7 项预检查通过。下一步：将 config.yaml 的 `mode` 设为 `full` 或 `longtime` 后重新运行，执行 Stage 1–5 完整 CPU 核心隔离测试。

## 附录

- 远程身份（检查 5 实际采集）：hostname=`***-SBCPTLCX3R100`，内核=`6.17.11-intel-ese-experimental-lts-rt`，登录用户=`***`
- SSH 认证方式：key；host key(SHA256)：SHA256:QBCNJTFuk9aXfZUgI59xMPwb741LlnWZbdahIVsv+mU（match(与 known_hosts 一致)）
- sudo 结论：结论: 可用（密码非交互）
- 原始命令与输出：`runs/run-20261125122038/commands.log`（已脱敏）

### 交付物清单（本次运行 run-20261125122038）

```
run-20261125122038/
    commands.log
  results/
  evidence/
```
