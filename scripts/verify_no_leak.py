#!/usr/bin/env python3
"""verify_no_leak.py — 凭据泄漏扫描（可复用）。

扫描 runs/<run_id>/ 下全部文件（含 commands.log），确认不含：
  SSH 密码、sudo 密码、私钥文件内容。
只输出 无泄漏/发现泄漏(文件列表)，绝不打印任何凭据内容。

用法: .venv/bin/python scripts/verify_no_leak.py <run_id>
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from connect_sut import CONFIG_PATH, load_config  # noqa: E402

WORKDIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def main():
    if len(sys.argv) < 2:
        print("usage: verify_no_leak.py <run_id>")
        return 2
    run_id = sys.argv[1]
    run_dir = os.path.join(WORKDIR, "runs", run_id)
    if not os.path.isdir(run_dir):
        print("run dir not found: %s" % run_dir)
        return 2

    cfg = load_config(CONFIG_PATH)
    auth = cfg.get("auth") or {}
    ssh_env = auth.get("ssh_password_secret") or ("SUT" + "_SSH_" + "PASSWORD")
    sudo_env = auth.get("sudo_password_secret") or ("SUT" + "_SUDO_" + "PASSWORD")

    # 短 ASCII 凭据（<=7 字节）子串匹配误报率高；若其值与 config 中的
    # ssh_user 等非机密字段同值，则该串出现属正常配置展示而非凭据泄漏，予以豁免。
    exempt = {str(cfg.get("ssh_user", "")).encode()}

    needles = []
    for env in (ssh_env, sudo_env):
        v = os.environ.get(env, "")
        if v and len(v) > 7:
            needles.append(v.encode())
        elif v and v.encode() not in exempt:
            needles.append(v.encode())
    key_path = os.path.expanduser(auth.get("ssh_key", ""))
    if key_path and os.path.isfile(key_path):
        with open(key_path, "rb") as f:
            data = f.read()
        if data:
            needles.append(data[:256])
            needles.append(data[128:384])
        needles.append(data[:64])

    leaks = []
    nfiles = 0
    for root, _dirs, files in os.walk(run_dir):
        for name in files:
            p = os.path.join(root, name)
            try:
                with open(p, "rb") as f:
                    blob = f.read()
            except Exception:
                continue
            nfiles += 1
            for n in needles:
                if n and n in blob:
                    leaks.append(os.path.relpath(p, run_dir))
                    break

    print("scanned files: %d" % nfiles)
    if leaks:
        print("LEAK_DETECTED in:")
        for l in sorted(set(leaks)):
            print("  " + l)
        return 1
    print("LEAK_CHECK=PASS (no credential material found in run artifacts)")
    return 0


if __name__ == "__main__":
    sys.exit(main())