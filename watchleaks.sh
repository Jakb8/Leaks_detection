#!/usr/bin/env bash
#
# WatchLeaks service manager
#   ./watchleaks.sh start      - start LAMP stack (Apache/MySQL) + web server + real-time sync workers
#   ./watchleaks.sh stop       - stop web server + workers
#   ./watchleaks.sh status     - show status of all services
#   ./watchleaks.sh sync       - run a single one-off sync now
#   ./watchleaks.sh scan       - run a single one-off leak scan now
#
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PHP="php"
WEB_HOST="${WEB_HOST:-0.0.0.0}"
WEB_PORT="${WEB_PORT:-8000}"
WEB_LOG="/tmp/watchleaks-web.log"
SYNC_LOG="/tmp/watchleaks-sync.log"
LEAK_LOG="/tmp/watchleaks-leaks.log"

is_active() {
    systemctl is-active --quiet "$1" 2>/dev/null
}

start_service() {
    local name="$1"
    if is_active "$name"; then
        echo "${name}: already running"
        return 0
    fi
    if ! systemctl start "$name" 2>/dev/null; then
        service "$name" start
    fi
    echo "${name}: started"
}

start_stack() {
    start_service apache2
    start_service mysql
    local i
    for i in $(seq 1 30); do
        if mysqladmin ping --silent >/dev/null 2>&1; then
            echo "MySQL: ready"
            return 0
        fi
        sleep 1
    done
    echo "MySQL: not ready after 30s" >&2
    return 1
}

start() {
    start_stack
    mkdir -p "${DIR}/var/sessions"
    if ! pgrep -f -- "-S ${WEB_HOST}:${WEB_PORT}" >/dev/null; then
        setsid "$PHP" -d session.save_path="${DIR}/var/sessions" -d session.gc_probability=0 -S "${WEB_HOST}:${WEB_PORT}" -t "${DIR}/public" >"${WEB_LOG}" 2>&1 </dev/null &
        echo "Web server started on http://${WEB_HOST}:${WEB_PORT}"
    else
        echo "Web server already running on ${WEB_HOST}:${WEB_PORT}"
    fi

    if ! pgrep -f "app:sync-feeds --loop" >/dev/null; then
        setsid "$PHP" "${DIR}/bin/console" app:sync-feeds --loop >"${SYNC_LOG}" 2>&1 </dev/null &
        echo "Attacks sync worker started (log: ${SYNC_LOG})"
    else
        echo "Attacks sync worker already running"
    fi

    if ! pgrep -f "app:scan-leaks --loop" >/dev/null; then
        setsid "$PHP" "${DIR}/bin/console" app:scan-leaks --loop >"${LEAK_LOG}" 2>&1 </dev/null &
        echo "Leak scan worker started (log: ${LEAK_LOG})"
    else
        echo "Leak scan worker already running"
    fi
    echo "WatchLeaks UI:   http://localhost:${WEB_PORT}"
    echo "phpMyAdmin UI:   http://localhost/phpmyadmin"
}

stop() {
    pkill -f "app:sync-feeds --loop" 2>/dev/null && echo "Attacks sync worker stopped" || echo "Attacks sync worker not running"
    pkill -f "app:scan-leaks --loop" 2>/dev/null && echo "Leak scan worker stopped" || echo "Leak scan worker not running"
    pkill -f -- "-S ${WEB_HOST}:${WEB_PORT}" 2>/dev/null && echo "Web server stopped" || echo "Web server not running"
}

status() {
    for svc in apache2 mysql; do
        if is_active "$svc"; then
            echo "${svc}: running"
        else
            echo "${svc}: stopped"
        fi
    done
    pgrep -f -- "-S ${WEB_HOST}:${WEB_PORT}" >/dev/null && echo "Web server: running" || echo "Web server: stopped"
    pgrep -f "app:sync-feeds --loop" >/dev/null && echo "Attacks sync worker: running" || echo "Attacks sync worker: stopped"
    pgrep -f "app:scan-leaks --loop" >/dev/null && echo "Leak scan worker: running" || echo "Leak scan worker: stopped"
    echo "WatchLeaks UI:   http://localhost:${WEB_PORT}"
    echo "phpMyAdmin UI:   http://localhost/phpmyadmin"
}

case "${1:-}" in
    start) start ;;
    stop) stop ;;
    restart) stop; sleep 1; start ;;
    status) status ;;
    sync) "$PHP" "${DIR}/bin/console" app:sync-feeds ;;
    scan) "$PHP" "${DIR}/bin/console" app:scan-leaks ;;
    *) echo "Usage: $0 {start|stop|restart|status|sync|scan}"; exit 1 ;;
esac
