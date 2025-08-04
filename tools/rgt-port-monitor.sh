#!/bin/bash

CONFIG_DIR="/root/bandwidth"
PORTS_FILE="$CONFIG_DIR/ports.txt"

mkdir -p "$CONFIG_DIR"
touch "$PORTS_FILE"

format_bytes() {
    local bytes=$1
    if ((bytes >= 1099511627776)); then
        printf "%.2f TB" "$(echo "$bytes / 1099511627776" | bc -l)"
    elif ((bytes >= 1073741824)); then
        printf "%.2f GB" "$(echo "$bytes / 1073741824" | bc -l)"
    elif ((bytes >= 1048576)); then
        printf "%.2f MB" "$(echo "$bytes / 1048576" | bc -l)"
    elif ((bytes >= 1024)); then
        printf "%.2f KB" "$(echo "$bytes / 1024" | bc -l)"
    else
        echo "$bytes B"
    fi
}

get_bytes() {
    local direction=$1
    local port=$2
    local proto=$3
    sudo iptables -L -v -n -x | \
        awk -v port=$port -v proto=$proto -v dir=$direction '
            ($dir == "INPUT" && $9 == proto && $11 == "dpt:" port) ||
            ($dir == "OUTPUT" && $9 == proto && $11 == "spt:" port) {
                sum += $2
            }
            END { print sum+0 }'
}

install() {
    echo "⚙️ Installing RGT Port Monitor..."
    read -p "Enter ports to monitor (format: <port>/<protocol>, separate with space): " input_ports

    for entry in $input_ports; do
        port="${entry%/*}"
        proto="${entry#*/}"

        [[ "$proto" != "tcp" && "$proto" != "udp" ]] && {
            echo "❌ Invalid protocol: $proto. Skipping."
            continue
        }

        echo "$port:$proto" >> "$PORTS_FILE"

        sudo iptables -I INPUT -p $proto --dport $port -j ACCEPT
        sudo iptables -I OUTPUT -p $proto --sport $port -j ACCEPT

        echo "0 0" > "$CONFIG_DIR/port_${port}_${proto}_usage.txt"
        echo "✅ Port $port/$proto added."
    done

    cat <<EOF > /etc/systemd/system/rgt-port-monitor.service
[Unit]
Description=RGT Port Bandwidth Monitor
After=network.target

[Service]
ExecStart=/bin/bash $PWD/$0 run
Restart=always

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reexec
    systemctl enable rgt-port-monitor.service
    systemctl start rgt-port-monitor.service

    echo "✅ Installation complete. Monitoring started."
}

addport() {
    port="$1"
    proto="$2"
    [[ -z "$port" || -z "$proto" ]] && {
        echo "Usage: $0 addport <port> <tcp|udp>"
        return 1
    }
    grep -q "^$port:$proto" "$PORTS_FILE" && {
        echo "Port already exists."
        return
    }

    echo "$port:$proto" >> "$PORTS_FILE"
    sudo iptables -I INPUT -p $proto --dport $port -j ACCEPT
    sudo iptables -I OUTPUT -p $proto --sport $port -j ACCEPT
    echo "0 0" > "$CONFIG_DIR/port_${port}_${proto}_usage.txt"
    echo "✅ Port $port/$proto added."
}

reset_port() {
    port="$1"
    proto="$2"
    echo "0 0" > "$CONFIG_DIR/port_${port}_${proto}_usage.txt"
    echo "✅ Usage reset for $port/$proto."
}

show_usage() {
    echo "🕒 $(date)"
    while IFS= read -r line; do
        port="${line%:*}"
        proto="${line#*:}"
        rx_file="$CONFIG_DIR/port_${port}_${proto}_usage.txt"

        old_rx=$(cut -d' ' -f1 "$rx_file")
        old_tx=$(cut -d' ' -f2 "$rx_file")

        rx=$(get_bytes INPUT $port $proto)
        tx=$(get_bytes OUTPUT $port $proto)

        new_rx=$((rx - old_rx))
        new_tx=$((tx - old_tx))

        echo "Port $port ($proto): RX $(format_bytes $new_rx) | TX $(format_bytes $new_tx)"
    done < "$PORTS_FILE"
}

run_monitor() {
    while true; do
        while IFS= read -r line; do
            port="${line%:*}"
            proto="${line#*:}"
            rx=$(get_bytes INPUT $port $proto)
            tx=$(get_bytes OUTPUT $port $proto)
            echo "$rx $tx" > "$CONFIG_DIR/port_${port}_${proto}_usage.txt"
        done < "$PORTS_FILE"
        sleep 30
    done
}

uninstall() {
    while IFS= read -r line; do
        port="${line%:*}"
        proto="${line#*:}"
        sudo iptables -D INPUT -p $proto --dport $port -j ACCEPT
        sudo iptables -D OUTPUT -p $proto --sport $port -j ACCEPT
        rm -f "$CONFIG_DIR/port_${port}_${proto}_usage.txt"
    done < "$PORTS_FILE"
    rm -f "$PORTS_FILE"
    systemctl disable --now rgt-port-monitor.service
    rm -f /etc/systemd/system/rgt-port-monitor.service
    echo "✅ Uninstalled."
}

case "$1" in
    install) install ;;
    addport) addport "$2" "$3" ;;
    show) show_usage ;;
    reset) reset_port "$2" "$3" ;;
    run) run_monitor ;;
    uninstall) uninstall ;;
    *)
        echo "Usage:"
        echo "  $0 install"
        echo "  $0 addport <port> <tcp|udp>"
        echo "  $0 show"
        echo "  $0 reset <port> <tcp|udp>"
        echo "  $0 uninstall"
        echo "  $0 run"
        ;;
esac
