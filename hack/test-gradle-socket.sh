#!/bin/bash
# Manual diagnostic script for Gradle socket operations inside cplt sandbox.
# Run this OUTSIDE the sandbox: ./hack/test-gradle-socket.sh
#
# For automated testing, see: tests/e2e_projects.rs (project_gradle_daemon_unix_socket)
set -e

CPLT="${1:-cplt}"
echo "Using cplt: $($CPLT --version)"
echo ""

# Project must be in a location with exec permissions (not /tmp or /var/folders).
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
PROJ="$REPO_DIR/.cplt-gradle-test-$$"
mkdir -p "$PROJ"
trap 'rm -rf "$PROJ"' EXIT

cd "$PROJ"
git init -b main >/dev/null 2>&1
echo '{}' > package.json
git add . && git commit -m init --allow-empty >/dev/null 2>&1

SOCK_DIR="$HOME/.gradle/daemon/cplt-socket-test"
mkdir -p "$SOCK_DIR"

cat > test-agent.sh << 'SCRIPT'
#!/bin/sh
set -eu
echo "=== Gradle Socket Test ==="
echo "JAVA_TOOL_OPTIONS=${JAVA_TOOL_OPTIONS:-unset}"
echo ""

# Test 1: Unix domain socket in ~/.gradle/daemon (Gradle daemon IPC)
SOCK_DIR="$HOME/.gradle/daemon/cplt-socket-test"
SOCK="$SOCK_DIR/test-daemon.sock"
rm -f "$SOCK"

echo "--- Test 1: UDS bind+connect in ~/.gradle/daemon ---"
python3 -c "
import socket, os, sys, threading, time

sock_path = '$SOCK'
try: os.unlink(sock_path)
except: pass

server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
server.bind(sock_path)
server.listen(1)
server.settimeout(5)

def client():
    time.sleep(0.5)
    c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    c.connect(sock_path)
    c.sendall(b'GRADLE_HELLO')
    resp = c.recv(1024)
    print(f'CLIENT got: {resp.decode()}')
    c.close()

t = threading.Thread(target=client)
t.start()

conn, _ = server.accept()
data = conn.recv(1024)
print(f'SERVER got: {data.decode()}')
conn.sendall(b'DAEMON_ACK')
conn.close()
t.join()
server.close()
os.unlink(sock_path)
print('UDS_TEST: PASS')
" 2>&1 && echo "RESULT:uds_gradle:OK" || echo "RESULT:uds_gradle:FAIL"

# Test 2: TCP localhost bind
echo ""
echo "--- Test 2: TCP localhost bind ---"
python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', 0))
s.listen(1)
port = s.getsockname()[1]
print(f'Bound to 127.0.0.1:{port}')
s.close()
print('TCP_BIND: PASS')
" 2>&1 && echo "RESULT:tcp_bind:OK" || echo "RESULT:tcp_bind:FAIL"

# Test 3: TCP IPv6 localhost bind
echo ""
echo "--- Test 3: TCP IPv6 ::1 bind ---"
python3 -c "
import socket
s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('::1', 0))
s.listen(1)
port = s.getsockname()[1]
print(f'Bound to [::1]:{port}')
s.close()
print('TCP6_BIND: PASS')
" 2>&1 && echo "RESULT:tcp6_bind:OK" || echo "RESULT:tcp6_bind:FAIL"

# Test 4: TCP 0.0.0.0 bind should be DENIED
echo ""
echo "--- Test 4: TCP 0.0.0.0 bind (should be denied) ---"
python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
try:
    s.bind(('0.0.0.0', 19876))
    s.listen(1)
    s.close()
    print('WILDCARD_BIND: ALLOWED (bad!)')
except Exception as e:
    print(f'WILDCARD_BIND: DENIED ({e}) - good!')
" 2>&1

# Test 5: UDS in scratch/tmp dir
echo ""
echo "--- Test 5: UDS in TMPDIR (scratch) ---"
TMP_SOCK="${TMPDIR:-/tmp}/cplt-test-$$.sock"
rm -f "$TMP_SOCK"
python3 -c "
import socket, os
sock_path = '$TMP_SOCK'
try: os.unlink(sock_path)
except: pass
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.bind(sock_path)
s.listen(1)
s.close()
os.unlink(sock_path)
print('UDS_TMP: PASS')
" 2>&1 && echo "RESULT:uds_tmp:OK" || echo "RESULT:uds_tmp:FAIL"

# Test 6: jenv shim exec
echo ""
echo "--- Test 6: jenv shim ---"
if [ -f "$HOME/.jenv/shims/java" ]; then
    if "$HOME/.jenv/shims/java" -version 2>&1 | head -1; then
        echo "RESULT:jenv_exec:OK"
    else
        echo "RESULT:jenv_exec:FAIL"
    fi
else
    echo "RESULT:jenv_exec:SKIP (no .jenv)"
fi

echo ""
echo "=== Done ==="
SCRIPT

chmod +x test-agent.sh

echo "Running inside cplt sandbox..."
echo ""
SHELL=/bin/sh $CPLT --yes --no-validate --project-dir "$PROJ" \
    --allow-jvm-attach \
    --agent shell \
    -- -c "$PROJ/test-agent.sh" 2>&1

# Cleanup socket dir
rm -f "$SOCK_DIR/test-daemon.sock"
rmdir "$SOCK_DIR" 2>/dev/null || true
