#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
export CPU_PYTHON="${CPU_PYTHON:-/root/.cache/uv/archive-v0/OvJCewHopHDXy8xF/bin/python}"
if [[ -f ../scripts/run_stage.py ]]; then
    DEFAULT_ENGINE="$(cd .. && pwd)"
else
    DEFAULT_ENGINE="$(dirname "$PWD")/cpu_ai_validation"
fi
export CPU_ENGINE="${CPU_ENGINE:-$DEFAULT_ENGINE}"
export CPU_AUTOMATIONS="${CPU_AUTOMATIONS:-$(dirname "$CPU_ENGINE")/openhands-automations}"
export OH_AUTOMATION_URL="${OH_AUTOMATION_URL:-http://127.0.0.1:18001/api/automation/v1}"
export WEB_BIND="${WEB_BIND:-127.0.0.1}" WEB_PORT="${WEB_PORT:-8080}"
export WEB_NO_AUTH="${WEB_NO_AUTH:-1}"
if [[ "$WEB_NO_AUTH" == 1 ]]; then
    export WEB_BIND=127.0.0.1
    WEB_PASSWORD=''
else
    read -rsp '网页 operator 登录密码（至少12字符）: ' WEB_PASSWORD; echo
fi
while true; do
    read -rsp 'SUT sudo 密码（不写入文件）: ' SUT_SUDO_PASSWORD
    echo
    if [[ -n "$SUT_SUDO_PASSWORD" ]]; then
        export SUT_SUDO_PASSWORD
        break
    fi
    echo "错误：SUT sudo 密码不能为空，请重新输入。"
done

echo "正在验证被测设备 sudo 权限..."

if ! (cd "$CPU_ENGINE" && "$CPU_PYTHON" -c '
from common.transport import execute
r = execute("id -u", root=True)
if r.returncode != 0 or r.stdout.strip() != "0":
    raise SystemExit(1)
'); then
    echo "错误：SUT sudo 权限验证失败，网页服务未启动。"
    exit 1
fi

echo "SUT sudo 权限验证通过"

OH_SESSION_KEY="${OH_SESSION_KEY:-${OPENHANDS_AUTOMATION_API_KEY:-}}"

if [[ -z "$OH_SESSION_KEY" ]]; then
    for pid in $(pgrep -f 'agent-server.*--port 18000' || true); do
        OH_SESSION_KEY="$(tr '\\0' '\\n' < /proc/$pid/environ 2>/dev/null | sed -n 's/^OPENHANDS_AUTOMATION_API_KEY=//p' || true)"
        [[ -n "$OH_SESSION_KEY" ]] && break
    done
fi

if [[ -z "$OH_SESSION_KEY" ]]; then
    read -rsp 'OpenHands session API key: ' OH_SESSION_KEY
    echo
else
    echo "OpenHands API Key 已自动加载"
fi
export WEB_PASSWORD SUT_SUDO_PASSWORD OH_SESSION_KEY
exec "$CPU_PYTHON" -u server.py
