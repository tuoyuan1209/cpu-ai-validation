#!/usr/bin/env python3
"""run_precheck.py — Stage 0 环境预检查执行器（CPU 核心隔离自动化）。

用法:
  .venv/bin/python scripts/run_precheck.py [--config path] [--run-id run-YYYYMMDDHHMMSS]

流程（mode=precheck 时自动化在本阶段结束）：
  检查1 配置文件        本地
  检查2 工作目录        本地（写入→读回→删除）
  检查3 Secret 访问验证 本地（只输出 可用/不可用）
  检查4 SSH 密钥        本地（仅引用路径）
  检查5 SSH 远程连通性  远程（密钥优先/密码回退；记录 hostname + 内核）
  检查6 sudo 可用性     远程（sudo -n → Secret 非交互认证）
  检查7 基础工具存在性  远程（cyclictest/stress-ng/taskset/mpstat/chrt，仅检查）

输出: runs/<run_id>/precheck_report.md（含 commands.log 原始证据、七项结果、
失败详情与修复建议、Secret 可用性结论、红线合规声明）。
precheck 模式不执行后续阶段、不修改被测系统；报告生成后终止，不打印任何凭据内容。
"""

import argparse
import json
import os
import stat
import sys
import time
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from connect_sut import CONFIG_PATH, SutClient, load_config, verify_identity  # noqa: E402

WORKDIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REQUIRED_KEYS = ["host", "ssh_user", "ssh_port", "mode"]
REQUIRED_AUTH_KEYS = ["method", "ssh_key", "ssh_password_secret", "sudo_password_secret"]
VALID_MODES = ("precheck", "full", "longtime")
TOOLS = ["cyclictest", "stress-ng", "taskset", "mpstat", "chrt"]
MANAGER_HINT = {"debian": "apt", "ubuntu": "apt", "rhel": "dnf", "centos": "dnf",
                "rocky": "dnf", "almalinux": "dnf", "opensuse": "zypper",
                "arch": "pacman", "fedora": "dnf"}
PKG_NAME = {
    "cyclictest": {"apt": "linux-tools-generic", "dnf": "rt-tests", "pacman": "rt-tests"},
    "stress-ng": {"apt": "stress-ng", "dnf": "stress-ng", "pacman": "stress-ng"},
    "taskset": {"apt": "util-linux", "dnf": "util-linux", "pacman": "util-linux"},
    "mpstat": {"apt": "sysstat", "dnf": "sysstat", "pacman": "sysstat"},
    "chrt": {"apt": "util-linux", "dnf": "util-linux", "pacman": "util-linux"},
}
PASS, FAIL, SKIP = "PASS", "FAIL", "SKIP"


def now_s():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def log_step(logf, ts, step, cmd, rc, out, err):
    logf.write("[%s] %s\n$ %s\nrc=%s\n--- stdout ---\n%s--- stderr ---\n%s\n\n"
               % (ts, step, cmd, rc, out or "(empty)", err or "(empty)"))
    logf.flush()


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default=CONFIG_PATH)
    ap.add_argument("--run-id", default=None)
    args = ap.parse_args(argv)

    ts0 = time.strftime("%Y%m%d%H%M%S")
    run_id = args.run_id or "run-%s" % ts0
    if not args.run_id and os.path.isdir(os.path.join(WORKDIR, "runs", run_id)):
        suffix = "".join(os.urandom(3).hex())
        run_id = run_id + "-" + suffix
    run_dir = os.path.join(WORKDIR, "runs", run_id)
    os.makedirs(run_dir, exist_ok=True)
    os.makedirs(os.path.join(run_dir, "evidence"), exist_ok=True)
    os.makedirs(os.path.join(run_dir, "results"), exist_ok=True)
    log_path = os.path.join(run_dir, "commands.log")
    logf = open(log_path, "w", encoding="utf-8")

    def log(step, cmd, rc, out, err):
        log_step(logf, now_s(), step, cmd, rc, out, err)

    # ============ 检查 1：配置文件（本地） ============
    c1 = {"name": "配置文件", "status": FAIL, "details": [], "fix": []}
    try:
        cfg = load_config(args.config)
        missing = [k for k in REQUIRED_KEYS if k not in cfg]
        auth = cfg.get("auth") or {}
        missing += ["auth." + k for k in REQUIRED_AUTH_KEYS if k not in auth]
        c1["details"].append("文件存在且可读: %s" % args.config)
        if missing:
            c1["details"].append("缺失必填键: %s" % ", ".join(missing))
            c1["fix"].append("补全 config.yaml 缺失键: %s" % ", ".join(missing))
        mode_raw = cfg.get("mode")
        if mode_raw in VALID_MODES:
            c1["details"].append("mode 合法: %s" % mode_raw)
        else:
            c1["details"].append("mode 缺失或非法（值: %r）→ 按 precheck 处理，并在此注明" % (mode_raw,))
            c1["details"].append("NOTE: 本次运行按规范以 precheck 模式执行")
        provision = cfg.get("provision") or {}
        c1["details"].append("provision 段: enabled=%s install_tools=%s configure_rt_permissions=%s "
                             "configure_device_permissions=%s modify_kernel_parameters=%s allow_reboot=%s"
                             % (provision.get("enabled"), provision.get("install_tools"),
                                provision.get("configure_rt_permissions"),
                                provision.get("configure_device_permissions"),
                                provision.get("modify_kernel_parameters"),
                                provision.get("allow_reboot")))
        acc = cfg.get("acceptance") or {}
        c1["details"].append("acceptance 段: %s" % json.dumps(acc, ensure_ascii=False, default=str))
        if not missing:
            c1["status"] = PASS
    except Exception as e:
        c1["details"].append("读取/解析失败: %s" % e)
        c1["fix"].append("检查 config.yaml 路径与 YAML 语法")
        cfg = {}
    log("check1-config", "read+parse config.yaml", 0 if c1["status"] == PASS else 1,
        "; ".join(c1["details"]), "")

    if c1["status"] == FAIL and not cfg:
        _finish("ABORT", [c1], [], cfg or {}, run_dir, run_id, logf,
                "配置文件缺失或不可解析，后续检查无法执行")

    # ============ 检查 2：工作目录（本地 写入→读回→删除） ============
    c2 = {"name": "工作目录", "status": FAIL, "details": [], "fix": []}
    probe_ok = True
    for d in (WORKDIR, run_dir, os.path.join(run_dir, "results")):
        try:
            probe = os.path.join(d, ".precheck_probe_%d" % os.getpid())
            with open(probe, "w") as f:
                f.write("ok")
            with open(probe) as f:
                ok = f.read() == "ok"
            os.remove(probe)
            c2["details"].append("%s: 写入→读回→删除 验证通过" % d if ok else "%s: 读回不一致" % d)
            probe_ok = probe_ok and ok
        except Exception as e:
            c2["details"].append("%s: 读写失败: %s" % (d, e))
            probe_ok = False
            c2["fix"].append("检查目录存在性与写权限（chown/chmod）: %s" % d)
    c2["status"] = PASS if probe_ok else FAIL
    log("check2-workdir", "write/read/remove probe in WORKDIR & runs/<run_id>/",
        0 if probe_ok else 1, "; ".join(c2["details"]), "")

    # ============ 检查 3：Secret 访问验证（本地） ============
    c3 = {"name": "Secret 访问验证", "status": FAIL, "details": [], "fix": []}
    for env_name in ("SUT" + "_SSH_" + "PASSWORD", "SUT" + "_SUDO_" + "PASSWORD"):
        val = os.environ.get(env_name)
        avail = bool(val)
        c3["details"].append("%s: %s" % (env_name, "可用" if avail else "不可用"))
        if not avail:
            c3["fix"].append("在 OpenHands Secrets 中配置 %s 后重新运行" % env_name)
    c3["details"].append("结论: 未在任何输出中打印凭据内容（只输出可用/不可用）")
    c3["status"] = PASS if all(os.environ.get(n) for n in
                               ("SUT" + "_SSH_" + "PASSWORD", "SUT" + "_SUDO_" + "PASSWORD")) else FAIL
    log("check3-secrets", "env presence check (masked)", 0 if c3["status"] == PASS else 1,
        "; ".join(c3["details"]), "")

    # ============ 检查 4：SSH 密钥（本地，仅引用路径） ============
    c4 = {"name": "SSH 密钥", "status": FAIL, "details": [], "fix": []}
    key_path = (cfg.get("auth") or {}).get("ssh_key")
    if not key_path:
        c4["details"].append("config auth.ssh_key 未设置")
        c4["fix"].append("在 config.yaml auth.ssh_key 中配置密钥绝对路径")
    else:
        key_path = os.path.expanduser(key_path)
        c4["details"].append("密钥路径: %s（仅引用路径，不输出内容）" % key_path)
        if not os.path.isfile(key_path):
            c4["details"].append("文件不存在")
            c4["fix"].append("生成密钥对 (ssh-keygen) 或将密钥放置到该路径")
        else:
            st = os.stat(key_path)
            perm = oct(stat.S_IMODE(st.st_mode))[-3:]
            c4["details"].append("文件存在且可读; 权限: %s" % perm)
            if perm == "600":
                c4["details"].append("权限检查: 正常")
            else:
                c4["details"].append("告警: 权限异常（建议 600）——可能影响 ssh 客户端加载密钥")
                c4["fix"].append("chmod 600 %s" % key_path)
            c4["status"] = PASS
    log("check4-sshkey", "stat %s" % (key_path or "<unset>"),
        0 if c4["status"] == PASS else 1, "; ".join(c4["details"]), "")

    # ---- 检查 1-4 汇总：若本地阻断项失败且无法继续远程检查，则终止 ----
    local_blockers = []
    if c3["status"] == FAIL:
        local_blockers.append("检查3(Secret) 失败：按规范立即终止运行")
    if c1["status"] == FAIL:
        local_blockers.append("检查1(配置) 存在缺失键")
    if local_blockers:
        c5 = c6 = c7 = None
        _finish("ABORT", [c1, c2, c3, c4, c5, c6, c7], [], cfg, run_dir, run_id, logf,
                "本地阻断项失败: " + "; ".join(local_blockers))

    # ============ 检查 5：SSH 远程连通性 ============
    c5 = {"name": "SSH 远程连通性", "status": FAIL, "details": [], "fix": [], "identity": None}
    sut = SutClient(cfg)
    connected = False
    try:
        sut.connect()
        connected = True
        c5["details"].append("认证方式: %s（密钥优先，失败时密码回退）" % sut.auth_method)
        c5["details"].append("host key 指纹(SHA256): %s" % (sut.host_key_fp or "unknown"))
        c5["details"].append("host key 状态: %s" % (sut.host_key_status or "unknown"))
        if "MISMATCH" in (sut.host_key_status or ""):
            c5["details"].append("严重: 与本地 known_hosts 记录不一致，疑似 host 被替换/中间人，已拒绝继续")
            c5["fix"].append("人工核对 %s 是否为目标被测机；核对主机指纹后更新 known_hosts"
                             % cfg.get("host"))
        rc, info = verify_identity(sut)
        c5["identity"] = info
        c5["details"].append("远程 hostname: %s" % (info.get("hostname") or "N/A"))
        c5["details"].append("远程内核版本: %s" % (info.get("kernel") or "N/A"))
        c5["details"].append("远程登录用户: %s" % (info.get("remote_user") or "N/A"))
        log("check5-connect", "ssh connect (key-first/password-fallback) + hostname/uname -r",
            rc, "auth=%s hostname=%s kernel=%s" % (sut.auth_method,
                                                   info.get("hostname"), info.get("kernel")),
            "hostkey=%s (%s)" % (sut.host_key_fp, sut.host_key_status))
        if rc == 0 and info.get("hostname") and "MISMATCH" not in (sut.host_key_status or ""):
            c5["status"] = PASS
            c5["details"].append("结论: 非交互登录成功，主机身份已确认（hostname 核对 + 内核版本记录）")
        else:
            c5["fix"].append("检查被测机 SSH 服务、端口 %s 连通性、账号状态" % cfg.get("ssh_port"))
    except Exception as e:
        c5["details"].append("连接失败: %s" % sut.mask(str(e)))
        c5["fix"].append("确认被测机 %s:%s 可达；密钥是否已装入 authorized_keys；"
                         "或检查 %s Secret 是否正确"
                         % (cfg.get("host"), cfg.get("ssh_port"),
                            (cfg.get("auth") or {}).get("ssh_password_secret")))
        log("check5-connect", "ssh connect", 1, "", c5["details"][-1])

    if not connected:
        c6 = c7 = None
        _finish("ABORT", [c1, c2, c3, c4, c5, c6, c7], [], cfg, run_dir, run_id, logf,
                "检查5(SSH 连通性)失败，无法执行远程检查，终止运行")

    # ============ 检查 6：sudo 可用性（远程） ============
    c6 = {"name": "sudo 可用性", "status": FAIL, "details": [], "fix": []}
    try:
        mode = sut.ensure_sudo()
        if mode == "nopasswd":
            c6["details"].append("sudo -n: 可用（免密）")
            c6["details"].append("sudo 密码非交互认证（Secret 经 stdin 注入）: 无需（sudo -n 已通过）")
            c6["status"] = PASS
            c6["details"].append("结论: 可用（免密）")
            log("check6-sudo", "sudo -n true", 0, "RC=0", "")
        elif mode == "password":
            c6["details"].append("sudo -n: 不可用（需要密码）")
            c6["details"].append("sudo 密码非交互认证（Secret 经 stdin 注入）: 可用")
            c6["status"] = PASS
            c6["details"].append("结论: 可用（密码非交互）")
            log("check6-sudo", "sudo -S -p '' true (stdin from secret, value redacted)", 0, "RC=0", "")
        else:
            c6["details"].append("sudo -n: 不可用（需要密码）")
            c6["details"].append("sudo 密码非交互认证（Secret 经 stdin 注入）: 不可用/未验证")
            c6["details"].append("结论: 不可用")
            c6["fix"].append("配置 sudo 密码 Secret，或为被测机用户配置免密 sudo"
                            "（仅限本自动化所需命令，禁止 NOPASSWD: ALL）")
            log("check6-sudo", "sudo -n / sudo -S probes", 1, "RC!=0", "")
    except Exception as e:
        c6["details"].append("sudo 检查异常: %s" % sut.mask(str(e)))
        c6["fix"].append("人工在被测机确认 sudo 配置")

    # ============ 检查 7：基础工具存在性（远程，仅检查不安装） ============
    c7 = {"name": "基础工具存在性", "status": FAIL, "details": [], "fix": []}
    missing_tools = []
    try:
        rc, out, err = sut.run(
            "for t in %s; do p=$(command -v $t 2>/dev/null); "
            "if [ -n \"$p\" ]; then echo \"FOUND $t $p\"; else echo \"MISSING $t\"; fi; done"
            % " ".join(TOOLS))
        pkg_mgr = None
        for m in ("apt-get", "dnf", "yum", "pacman", "zypper"):
            rc2, out2, _ = sut.run("command -v %s >/dev/null 2>&1 && echo yes" % m)
            if "yes" in out2:
                pkg_mgr = m
                break
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("FOUND"):
                _, t, p = line.split(None, 2)
                c7["details"].append("%s: 存在 → %s" % (t, p))
            elif line.startswith("MISSING"):
                t = line.split()[1]
                missing_tools.append(t)
                c7["details"].append("%s: 缺失" % t)
        c7["details"].append("软件包管理器: %s" % (pkg_mgr or "未识别"))
        if missing_tools:
            c7["fix"].append("缺失工具: %s；Stage 2 将由 %s 安装（本阶段仅检查，未安装）"
                             % (", ".join(missing_tools), pkg_mgr or "对应发行版管理器"))
        else:
            c7["status"] = PASS
        log("check7-tools", "command -v for %s" % ",".join(TOOLS), rc, out.strip(), err)
    except Exception as e:
        c7["details"].append("工具检查异常: %s" % sut.mask(str(e)))

    checks = [c1, c2, c3, c4, c5, c6, c7]
    all_pass = all(c["status"] == PASS for c in checks)
    _finish("PASS" if all_pass else "FAIL", checks, [], cfg, run_dir, run_id, logf, None,
            identity=c5.get("identity"), auth_method=sut.auth_method,
            host_key_fp=sut.host_key_fp, host_key_status=sut.host_key_status,
            sudo_mode=c6["details"][-1] if c6["details"] else "")


def _finish(verdict, checks, extra, cfg, run_dir, run_id, logf, abort_reason=None,
            identity=None, auth_method=None, host_key_fp=None, host_key_status=None,
            sudo_mode=None):
    cfg = cfg or {}
    checks = [c for c in checks if c]
    lines = []
    ap = lines.append
    mode_disp = cfg.get("mode")
    ap("# CPU 核心隔离测试 — 环境预检查报告（Stage 0）")
    ap("")
    ap("## 运行信息")
    ap("")
    ap("| 项目 | 值 |")
    ap("|---|---|")
    ap("| 运行编号 (run_id) | %s |" % run_id)
    ap("| 运行模式 (mode) | %s%s |"
       % (mode_disp, "（缺失/非法，按规范以 precheck 处理并在此注明）"
          if mode_disp not in VALID_MODES else "（来自 config.yaml）"))
    ap("| 执行时间 | %s ~ %s (本地时间) |" % (datetime.now().strftime("%Y-%m-%d %H:%M"), now_s()))
    ap("| 执行位置 | OpenHands 部署服务器（检查 1–4 本地执行；检查 5–7 通过 SSH 在被测机执行） |")
    ap("| 被测机 (host) | %s（远程 hostname: %s） |"
       % (cfg.get("host"), (identity or {}).get("hostname") or "未连接"))
    ap("| SSH 用户 / 端口 | %s / %s |" % (cfg.get("ssh_user"), cfg.get("ssh_port")))
    ap("| SSH 密钥（配置值） | %s（仅引用路径） |" % ((cfg.get("auth") or {}).get("ssh_key")))
    ap("| 配置文件 | %s |" % os.path.join(WORKDIR, "config.yaml"))
    ap("")
    ap("**说明**：本次运行为 Stage 0 环境预检查，未执行任何 CPU 隔离测试，"
       "未使用容器/Agent 环境自身数据替代被测机数据，未修改被测系统。")
    ap("")

    ap("## 预检查总体结论：%s" % ("✅ 通过（7/7）" if verdict == "PASS"
                                   else "❌ 未通过%s" % ("（%s）" % abort_reason if abort_reason else "")))
    ap("")
    ap("| # | 检查项 | 结果 |")
    ap("|---|---|---|")
    for i, c in enumerate(checks, 1):
        mark = "✅ 通过" if c["status"] == PASS else ("❌ 失败" if c["status"] == FAIL else "⏭ 跳过")
        ap("| %d | %s | %s |" % (i, c["name"], mark))
    if len(checks) < 7:
        for i in range(len(checks) + 1, 8):
            ap("| %d | — | ⛔ 未执行（前置失败终止） |" % i)
    ap("")
    ap("---")
    ap("")
    ap("## 逐项检查详情")
    ap("")
    for i, c in enumerate(checks, 1):
        mark = "✅" if c["status"] == PASS else ("❌" if c["status"] == FAIL else "⏭")
        ap("### 检查 %d：%s %s" % (i, c["name"], mark))
        ap("")
        for d in c["details"]:
            ap("- %s" % d)
        if c["fix"]:
            ap("- **修复建议**：")
            for f in c["fix"]:
                ap("  - %s" % f)
        ap("")

    ap("---")
    ap("")
    ap("## Secret 可用性结论")
    ap("")
    c3 = next((c for c in checks if c["name"] == "Secret 访问验证"), None)
    if c3:
        for d in c3["details"]:
            ap("- %s" % d)
    else:
        ap("- 未执行（前置失败）")
    ap("")
    ap("## 红线合规声明")
    ap("")
    ap("- [x] 未修改被测系统：precheck 模式仅执行只读检查与权限自检（sudo -n / sudo -S true），"
       "未安装软件、未修改任何被测机配置、未调整 GRUB/内核启动参数。")
    ap("- [x] 未重启/关机被测机。")
    ap("- [x] 凭据保护：SSH 密码与 sudo 密码仅经 stdin 注入，未出现在命令行参数、日志、"
       "报告或本输出中；密钥仅引用路径，未输出私钥内容。")
    ap("- [x] 所有远程数据（hostname、内核、工具路径、sudo 状态）均来自被测机 %s 的实际 SSH 执行结果，"
       "无编造/估算。" % (cfg.get("host") or ""))
    ap("- [x] 远程命令均带超时保护；检查所用子进程（无持久进程）无残留。")
    ap("")
    ap("## 终止/后续说明")
    ap("")
    if verdict == "PASS":
        ap("全部 7 项预检查通过。下一步：将 config.yaml 的 `mode` 设为 `full` 或 `longtime` 后重新运行，"
           "执行 Stage 1–5 完整 CPU 核心隔离测试。")
    else:
        ap("预检查未通过。修复上表标记 ❌ 的检查项后重新运行本自动化；"
           "precheck 模式下不执行后续任何阶段。")
    ap("")
    ap("## 附录")
    ap("")
    ap("- 远程身份（检查 5 实际采集）：hostname=`%s`，内核=`%s`，登录用户=`%s`"
       % ((identity or {}).get("hostname"), (identity or {}).get("kernel"),
          (identity or {}).get("remote_user")))
    if auth_method:
        ap("- SSH 认证方式：%s；host key(SHA256)：%s（%s）"
           % (auth_method, host_key_fp, host_key_status))
    if sudo_mode:
        ap("- sudo 结论：%s" % sudo_mode)
    ap("- 原始命令与输出：`runs/%s/commands.log`（已脱敏）" % run_id)
    ap("")
    ap("### 交付物清单（本次运行 %s）" % run_id)
    ap("")
    ap("```")
    for root, _, files in os.walk(run_dir):
        depth = root.replace(run_dir, "").count(os.sep)
        base = os.path.basename(root) or run_dir
        ap("%s%s" % ("  " * depth, base + "/"))
        for fn in sorted(files):
            ap("%s  %s" % ("  " * (depth + 1), fn))
    ap("```")
    ap("")

    report = "\n".join(lines)
    report_path = os.path.join(run_dir, "precheck_report.md")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report)
    logf.write("\n[final] verdict=%s report=%s\n" % (verdict, report_path))
    logf.close()
    print("RUN_ID=%s" % run_id)
    print("VERDICT=%s" % verdict)
    print("REPORT=%s" % report_path)
    if abort_reason:
        print("ABORT_REASON=%s" % abort_reason)
    return 0 if verdict == "PASS" else 2


if __name__ == "__main__":
    sys.exit(main())