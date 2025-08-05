#!/bin/bash
# Check if the script is run as root
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root"
    sleep 1
    exit 1
fi

# Define colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

# Define paths
CONFIG_DIR="/root/rgt-core"
SERVICE_DIR="/etc/systemd/system"
RGT_BIN="${CONFIG_DIR}/rgt"
SCRIPT_PATH="/usr/local/bin/RGT"

# Function to press key to continue
function press_key() {
    echo
    read -rp "Press any key to continue..."
}

# Function to colorize text
function colorize() {
    local color="$1"
    local text="$2"
    local style="${3:-normal}"
    local black="\033[30m"
    local red="\033[31m"
    local green="\033[32m"
    local yellow="\033[33m"
    local blue="\033[34m"
    local magenta="\033[35m"
    local cyan="\033[36m"
    local white="\033[37m"
    local reset="\033[0m"
    local normal="\033[0m"
    local bold="\033[1m"
    local underline="\033[4m"
    local color_code
    case $color in
        black) color_code=$black ;;
        red) color_code=$red ;;
        green) color_code=$green ;;
        yellow) color_code=$yellow ;;
        blue) color_code=$blue ;;
        magenta) color_code=$magenta ;;
        cyan) color_code=$cyan ;;
        white) color_code=$white ;;
        *) color_code=$reset ;;
    esac
    local style_code
    case $style in
        bold) style_code=$bold ;;
        underline) style_code=$underline ;;
        normal | *) style_code=$normal ;;
    esac
    echo -e "${style_code}${color_code}${text}${reset}"
}

# Function to detect network interface
function detect_network_interface() {
    local interface=$(ip link | grep -E '^[0-9]+: (eth[0-9]+|ens[0-9]+)' | awk '{print $2}' | cut -d':' -f1 | head -n 1)
    if [[ -z "$interface" ]]; then
        colorize red "No network interface found."
        press_key
        exit 1
    fi
    echo "$interface"
}

# Function to install dependencies
function install_dependencies() {
    if ! command -v unzip &> /dev/null; then
        colorize yellow "Installing unzip..."
        apt-get update
        apt-get install -y unzip || { colorize red "Failed to install unzip"; press_key; exit 1; }
    fi
    if ! command -v jq &> /dev/null; then
        colorize yellow "Installing jq..."
        apt-get update
        apt-get install -y jq || { colorize red "Failed to install jq"; press_key; exit 1; }
    fi
    if ! command -v curl &> /dev/null; then
        colorize yellow "Installing curl..."
        apt-get update
        apt-get install -y curl || { colorize red "Failed to install curl"; press_key; exit 1; }
    fi
    if ! command -v ip &> /dev/null; then
        colorize yellow "Installing iproute2..."
        apt-get update
        apt-get install -y iproute2 || { colorize red "Failed to install iproute2"; press_key; exit 1; }
    fi
    if ! command -v brctl &> /dev/null; then
        colorize yellow "Installing bridge-utils..."
        apt-get update
        apt-get install -y bridge-utils || { colorize red "Failed to install bridge-utils"; press_key; exit 1; }
    fi
    if ! command -v haproxy &> /dev/null; then
        colorize yellow "Installing haproxy..."
        apt-get update
        apt-get install -y haproxy || { colorize red "Failed to install haproxy"; press_key; exit 1; }
    fi
}

# Function to display manual download instructions
function manual_download_instructions() {
    colorize red "Failed to download RGT core from GitHub due to network restrictions."
    echo
    colorize yellow "Please follow these steps to manually download and install RGT core:"
    echo
    echo "1. Download the 'RGT-x86-64-linux.zip' file from the following URL:"
    echo
    colorize yellow "   https://github.com/black-sec/RGT/raw/main/core/RGT-x86-64-linux.zip"
    echo
    echo "   You can use a browser or wget on a system with access:"
    echo "   wget https://github.com/black-sec/RGT/raw/main/core/RGT-x86-64-linux.zip"
    echo
    echo "2. Upload the downloaded file to /root/ on the server using SFTP."
    echo
    echo "3. Log in to the server via SSH and extract the file:"
    echo
    echo "   mkdir -p /root/rgt-core"
    echo "   unzip /root/RGT-x86-64-linux.zip -d /root/rgt-core"
    echo "   mv /root/rgt-core/rgt /root/rgt-core/rgt"
    echo "   chmod +x /root/rgt-core/rgt"
    echo "   rm /root/RGT-x86-64-linux.zip"
    echo
    echo "4. Re-run the script to continue setup."
    press_key
    exit 1
}

# Function to validate downloaded zip file
function validate_zip_file() {
    local zip_file="$1"
    if [[ ! -f "$zip_file" ]]; then
        colorize red "Downloaded file does not exist."
        return 1
    fi
    if ! file "$zip_file" | grep -q "Zip archive data"; then
        colorize red "Downloaded file is not a valid zip archive."
        return 1
    fi
    if [[ $(stat -c %s "$zip_file") -lt 1000 ]]; then
        colorize red "Downloaded file is too small and not valid."
        return 1
    fi
    return 0
}

# Function to download and install rgt
function download_and_extract_rgt() {
    if [[ -f "${RGT_BIN}" ]] && [[ -x "${RGT_BIN}" ]]; then
        colorize green "RGT is already installed and executable." bold
        sleep 1
        return 0
    fi
    DOWNLOAD_URL="https://github.com/black-sec/RGT/raw/main/core/RGT-x86-64-linux.zip"
    DOWNLOAD_DIR=$(mktemp -d)
    ZIP_FILE="$DOWNLOAD_DIR/rgt.zip"
    colorize yellow "Downloading RGT core..."
    if ! curl -sSL -o "$ZIP_FILE" "$DOWNLOAD_URL"; then
        rm -rf "$DOWNLOAD_DIR"
        manual_download_instructions
    fi
    if ! validate_zip_file "$ZIP_FILE"; then
        rm -rf "$DOWNLOAD_DIR"
        manual_download_instructions
    fi
    colorize yellow "Extracting RGT..."
    mkdir -p "$CONFIG_DIR"
    if ! unzip -q "$ZIP_FILE" -d "$CONFIG_DIR"; then
        colorize red "Failed to extract RGT"
        rm -rf "$DOWNLOAD_DIR"
        manual_download_instructions
    fi
    if [[ ! -f "${CONFIG_DIR}/rgt" ]]; then
        colorize red "RGT binary not found in zip file"
        rm -rf "$DOWNLOAD_DIR"
        manual_download_instructions
    fi
    mv "${CONFIG_DIR}/rgt" "${RGT_BIN}"
    chmod +x "${RGT_BIN}"
    rm -rf "$DOWNLOAD_DIR"
    if [[ ! -x "${RGT_BIN}" ]]; then
        colorize red "RGT binary is not executable"
        manual_download_instructions
    fi
    colorize green "RGT installed successfully." bold
    cp "$0" "${SCRIPT_PATH}"
    chmod +x "${SCRIPT_PATH}"
    colorize green "Script is now executable as 'RGT' command." bold
}

# Function to update script
function update_script() {
    clear
    colorize cyan "Updating RGT Manager Script" bold
    echo
    UPDATE_URL="https://github.com/black-sec/RGT/raw/main/rgt_manager.sh"
    TEMP_SCRIPT="/tmp/rgt_manager.sh"
    colorize yellow "Downloading updated script..."
    if ! curl -sSL -o "$TEMP_SCRIPT" "$UPDATE_URL"; then
        colorize red "Failed to download updated script. Please check network or URL."
        press_key
        return 1
    fi
    if ! grep -q "RGT Tunnel" "$TEMP_SCRIPT"; then
        colorize red "Downloaded file does not appear to be a valid RGT script."
        rm -f "$TEMP_SCRIPT"
        press_key
        return 1
    fi
    mv "$TEMP_SCRIPT" "${SCRIPT_PATH}"
    chmod +x "${SCRIPT_PATH}"
    colorize green "RGT Manager Script updated successfully."
    colorize yellow "Please re-run the script with 'RGT' command to use the updated version."
    press_key
    exit 0
}

# Function to check if a port is in use
function check_port() {
    local port=$1
    local transport=$2
    if [[ "$transport" == "tcp" ]]; then
        ss -tlnp "sport = :$port" | grep -q "$port" && return 0 || return 1
    elif [[ "$transport" == "udp" ]]; then
        ss -ulnp "sport = :$port" | grep -q "$port" && return 0 || return 1
    else
        return 1
    fi
}

# Function to validate IPv6 address
function check_ipv6() {
    local ip=$1
    ip="${ip#[}"
    ip="${ip%]}"
    ipv6_pattern="^([0-9a-fA-F]{1,4}:){7}([0-9a-fA-F]{1,4}|:)$|^(([0-9a-fA-F]{1,4}:){1,7}|:):((:[0-9a-fA-F]{1,4}){1,7}|:)$"
    [[ $ip =~ $ipv6_pattern ]] && return 0 || return 1
}

# Function to validate IPv4 address
function check_ipv4() {
    local ip=$1
    ipv4_pattern="^([0-9]{1,3}\.){3}[0-9]{1,3}$"
    if [[ $ip =~ $ipv4_pattern ]]; then
        IFS='.' read -r -a octets <<< "$ip"
        for octet in "${octets[@]}"; do
            [[ $octet -gt 255 ]] && return 1
        done
        return 0
    fi
    return 1
}

# Function to check for consecutive errors and restart
function check_consecutive_errors() {
    local service_name="$1"
    local tunnel_name=$(echo "$service_name" | sed 's/RGT-//;s/.service//')
    local logs=$(journalctl -u "$service_name" -n 50 --no-pager | tail -n 2)
    local error_count=$(echo "$logs" | grep -c "ERROR")
    if [[ $error_count -ge 2 ]]; then
        colorize yellow "Two consecutive errors detected in $service_name logs. Restarting..."
        systemctl restart "$service_name"
        if [[ $? -eq 0 ]]; then
            colorize green "Tunnel $tunnel_name restarted successfully due to consecutive errors."
        else
            colorize red "Failed to restart tunnel $tunnel_name."
        fi
    fi
}

# Function to validate VXLAN setup
function validate_vxlan_setup() {
    local local_ip=$1
    local remote_ip=$2
    local tunnel_port=$3
    local network_interface=$4
    local vxlan_id=$5
    if ! ip link show "$network_interface" up &> /dev/null; then
        colorize red "Network interface $network_interface is not up."
        return 1
    fi
    if ! lsmod | grep -q vxlan; then
        colorize yellow "Loading VXLAN kernel module..."
        modprobe vxlan || { colorize red "Failed to load VXLAN module"; return 1; }
    fi
    if [[ -n "$(ip addr show | grep -w "$local_ip" | grep -v "$network_interface")" ]]; then
        colorize red "IP address $local_ip is already in use on another interface."
        return 1
    fi
    return 0
}

# Function to configure Direct tunnel
function direct_server_configuration() {
    clear
    colorize cyan "Configuring Direct Tunnel" bold
    echo
    colorize cyan "Select Server Type:" bold
    echo "1) Iran Server"
    echo "2) Kharej Server"
    read -p "Enter choice: " server_type
    case $server_type in
        1) configure_direct_iran ;;
        2) configure_direct_kharej ;;
        *) colorize red "Invalid option!" && press_key && return 1 ;;
    esac
}

# Define HAProxy config path
HAPROXY_CFG="/etc/haproxy/haproxy.cfg"

# Function to configure Direct tunnel for Iran server
function configure_direct_iran() {
    read -p "[*] Enter tunnel name (e.g., direct-tunnel): " tunnel_name
    tunnel_name=$(echo "$tunnel_name" | tr ' ' '-' | tr -d '[:space:]')
    if [[ -z "$tunnel_name" ]]; then
        colorize red "Tunnel name cannot be empty."
        press_key
        return 1
    fi
    if [[ -f "${CONFIG_DIR}/direct-iran-${tunnel_name}.conf" ]]; then
        colorize red "Tunnel with name '$tunnel_name' already exists."
        press_key
        return 1
    fi

    echo "Iran server address type:"
    echo "1) IPv4"
    echo "2) IPv6"
    read -p "Enter choice: " ip_choice
    case $ip_choice in
        1) ip_type="ipv4" ;;
        2) ip_type="ipv6" ;;
        *) colorize red "Invalid option! Defaulting to IPv4"; ip_type="ipv4" ;;
    esac

    if [[ "$ip_type" == "ipv4" ]]; then
        local_ip=$(ip -4 addr show $(detect_network_interface) | grep inet | awk '{print $2}' | cut -d'/' -f1)
    else
        local_ip=$(ip -6 addr show $(detect_network_interface) | grep inet6 | grep global | awk '{print $2}' | cut -d'/' -f1)
    fi
    if [[ -z "$local_ip" ]]; then
        colorize red "Server IP could not be detected."
        press_key
        return 1
    fi
    colorize green "Iran server address: $local_ip"

    read -p "[*] Enter Kharej server IP (IPv4 or [IPv6]): " remote_ip
    [[ -z "$remote_ip" ]] && { colorize red "Server address cannot be empty."; press_key; return 1; }
    if check_ipv6 "$remote_ip"; then
        remote_ip="${remote_ip#[}"
        remote_ip="${remote_ip%]}"
    elif ! check_ipv4 "$remote_ip"; then
        colorize red "Invalid IP address format."
        press_key
        return 1
    fi

    while true; do
        read -p "[*] Enter tunnel port (e.g., 4790): " tunnel_port
        if [[ "$tunnel_port" =~ ^[0-9]+$ ]] && [ "$tunnel_port" -gt 22 ] && [ "$tunnel_port" -le 65535 ]; then
            break
        else
            colorize red "Enter a valid port (23-65535)"
        fi
    done

    network_interface=$(detect_network_interface)
    colorize green "Detected network interface: $network_interface"

    read -p "[*] Enter Iran bridge IP address (default: 10.0.10.1): " iran_bridge_ip
    [[ -z "$iran_bridge_ip" ]] && iran_bridge_ip="10.0.10.1"
    if [[ ! "$iran_bridge_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        colorize red "Invalid bridge IP address (must be in format 10.0.10.x)."
        press_key
        return 1
    fi
    iran_bridge_ip="${iran_bridge_ip}/24"
    colorize green "Iran bridge IP: $iran_bridge_ip"

    read -p "[*] Enter Kharej bridge IP address (default: 10.0.10.2): " kharej_bridge_ip
    [[ -z "$kharej_bridge_ip" ]] && kharej_bridge_ip="10.0.10.2"
    if [[ ! "$kharej_bridge_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        colorize red "Invalid bridge IP address (must be in format 10.0.10.x)."
        press_key
        return 1
    fi
    kharej_bridge_ip="${kharej_bridge_ip}/24"
    colorize green "Kharej bridge IP: $kharej_bridge_ip"

    read -p "[*] Enter VXLAN ID (default: 100): " vxlan_id
    [[ -z "$vxlan_id" ]] && vxlan_id=100
    if [[ ! "$vxlan_id" =~ ^[0-9]+$ ]] || [ "$vxlan_id" -lt 1 ] || [ "$vxlan_id" -gt 16777215 ]; then
        colorize red "Invalid VXLAN ID. Must be between 1 and 16777215."
        press_key
        return 1
    fi

    if ! validate_vxlan_setup "$local_ip" "$remote_ip" "$tunnel_port" "$network_interface" "$vxlan_id"; then
        press_key
        return 1
    fi

    read -p "[*] Enter service ports (e.g., 8008,8080): " input_ports
    input_ports=$(echo "$input_ports" | tr -d ' ')
    IFS=',' read -r -a ports <<< "$input_ports"
    declare -a config_ports
    for port in "${ports[@]}"; do
        if [[ "$port" =~ ^[0-9]+$ ]] && [ "$port" -gt 22 ] && [ "$port" -le 65535 ]; then
            if check_port "$port" "tcp"; then
                colorize red "Port $port is in use."
            else
                config_ports+=("$port")
                colorize green "Port $port added."
            fi
        else
            colorize red "Port $port is invalid. Must be between 23-65535."
        fi
    done
    if [[ ${#config_ports[@]} -eq 0 ]]; then
        colorize red "No valid ports entered. Exiting..."
        sleep 2
        return 1
    fi

    # Setup VXLAN and bridge
    ip link add vxlan${vxlan_id} type vxlan id $vxlan_id local "$local_ip" remote "$remote_ip" dstport "$tunnel_port" dev "$network_interface"
    if [[ $? -ne 0 ]]; then
        colorize red "Failed to create VXLAN interface."
        press_key
        return 1
    fi
    ip link add name br${vxlan_id} type bridge
    if [[ $? -ne 0 ]]; then
        colorize red "Failed to create bridge."
        ip link delete vxlan${vxlan_id} 2>/dev/null
        press_key
        return 1
    fi
    ip link set vxlan${vxlan_id} master br${vxlan_id}
    if [[ $? -ne 0 ]]; then
        colorize red "Failed to attach VXLAN to bridge."
        ip link delete vxlan${vxlan_id} 2>/dev/null
        ip link delete br${vxlan_id} 2>/dev/null
        press_key
        return 1
    fi
    ip link set br${vxlan_id} up
    if [[ $? -ne 0 ]]; then
        colorize red "Failed to bring up bridge."
        ip link delete vxlan${vxlan_id} 2>/dev/null
        ip link delete br${vxlan_id} 2>/dev/null
        press_key
        return 1
    fi
    ip link set vxlan${vxlan_id} up
    if [[ $? -ne 0 ]]; then
        colorize red "Failed to bring up VXLAN."
        ip link delete vxlan${vxlan_id} 2>/dev/null
        ip link delete br${vxlan_id} 2>/dev/null
        press_key
        return 1
    fi
    ip addr flush dev br${vxlan_id} 2>/dev/null
    ip addr add "$iran_bridge_ip" dev br${vxlan_id}
    if [[ $? -ne 0 ]]; then
        colorize red "Failed to assign IP to bridge."
        ip link delete vxlan${vxlan_id} 2>/dev/null
        ip link delete br${vxlan_id} 2>/dev/null
        press_key
        return 1
    fi

    # Ensure HAProxy config file exists
    if [[ ! -f "$HAPROXY_CFG" ]]; then
        colorize yellow "HAProxy configuration file not found. Creating a new one..."
        mkdir -p /etc/haproxy
        cat << EOF > "$HAPROXY_CFG"
global
    log /dev/log local0 warning
    maxconn 4096
    user haproxy
    group haproxy
    daemon

defaults
    log global
    mode tcp
    option tcplog
    timeout connect 5000ms
    timeout client 50000ms
    timeout server 50000ms
    timeout check 5000ms

EOF
        chown haproxy:haproxy "$HAPROXY_CFG"
        chmod 644 "$HAPROXY_CFG"
    fi

    # Check if tunnel already exists in HAProxy config
    if grep -q "# Tunnel-specific configuration for $tunnel_name" "$HAPROXY_CFG"; then
        colorize red "Tunnel $tunnel_name already exists in HAProxy configuration."
        ip link delete vxlan${vxlan_id} 2>/dev/null
        ip link delete br${vxlan_id} 2>/dev/null
        press_key
        return 1
    fi

    # Create a temporary file for HAProxy config
    temp_haproxy_cfg=$(mktemp)
    cp "$HAPROXY_CFG" "$temp_haproxy_cfg"

    # Append tunnel-specific HAProxy config
    for port in "${config_ports[@]}"; do
        cat << EOF >> "$temp_haproxy_cfg"
# Tunnel-specific configuration for $tunnel_name
frontend RGT_frontend_${port}
    bind *:${port}
    mode tcp
    option tcplog
    default_backend RGT_backend_${port}

backend RGT_backend_${port}
    mode tcp
    option tcp-check
    server RGT_server ${kharej_bridge_ip%/*}:${port} check inter 5000 rise 2 fall 3

EOF
    done

    # Validate HAProxy config
    if ! haproxy -c -f "$temp_haproxy_cfg"; then
        colorize red "HAProxy configuration is invalid. Reverting changes."
        rm -f "$temp_haproxy_cfg"
        ip link delete vxlan${vxlan_id} 2>/dev/null
        ip link delete br${vxlan_id} 2>/dev/null
        press_key
        return 1
    fi

    # Apply new HAProxy config
    mv "$temp_haproxy_cfg" "$HAPROXY_CFG"
    if [[ $? -ne 0 ]]; then
        colorize red "Failed to update HAProxy configuration."
        ip link delete vxlan${vxlan_id} 2>/dev/null
        ip link delete br${vxlan_id} 2>/dev/null
        rm -f "$temp_haproxy_cfg"
        press_key
        return 1
    fi

    # Save tunnel configuration
    config_file="${CONFIG_DIR}/direct-iran-${tunnel_name}.conf"
    cat << EOF > "$config_file"
vxlan_id=$vxlan_id
local_ip=$local_ip
remote_ip=$remote_ip
dstport=$tunnel_port
network_interface=$network_interface
iran_bridge_ip=$iran_bridge_ip
kharej_bridge_ip=$kharej_bridge_ip
ports=${input_ports}
EOF

    # Create systemd service
    service_file="${SERVICE_DIR}/RGT-direct-iran-${tunnel_name}.service"
    cat << EOF > "$service_file"
[Unit]
Description=RGT Direct Iran Tunnel $tunnel_name
After=network.target

[Service]
Type=oneshot
ExecStart=/bin/bash -c '
  ip link show vxlan${vxlan_id} >/dev/null 2>&1 || ip link add vxlan${vxlan_id} type vxlan id ${vxlan_id} local $local_ip remote $remote_ip dstport $tunnel_port dev $network_interface;
  ip link show br${vxlan_id} >/dev/null 2>&1 || ip link add name br${vxlan_id} type bridge;
  ip link set vxlan${vxlan_id} master br${vxlan_id};
  ip link set br${vxlan_id} up;
  ip link set vxlan${vxlan_id} up;
  ip addr flush dev br${vxlan_id} 2>/dev/null;
  ip addr add $iran_bridge_ip dev br${vxlan_id};
  systemctl restart haproxy
'
ExecStop=/bin/bash -c '
  ip link delete vxlan${vxlan_id} 2>/dev/null;
  ip link delete br${vxlan_id} 2>/dev/null;
  systemctl restart haproxy
'
RemainAfterExit=yes


[Install]
WantedBy=multi-user.target
EOF

    # Reload systemd and start services
    systemctl daemon-reload
    if [[ $? -ne 0 ]]; then
        colorize red "Failed to reload systemd"
        press_key
        return 1
    fi
    systemctl enable "RGT-direct-iran-${tunnel_name}.service"
    if [[ $? -ne 0 ]]; then
        colorize red "Failed to enable service"
        press_key
        return 1
    fi
    systemctl start "RGT-direct-iran-${tunnel_name}.service"
    if [[ $? -ne 0 ]]; then
        colorize red "Failed to start service. Check 'systemctl status RGT-direct-iran-${tunnel_name}.service' for details"
        press_key
        return 1
    fi
    systemctl restart haproxy
    if [[ $? -ne 0 ]]; then
        colorize red "Failed to restart HAProxy"
        press_key
        return 1
    fi
    colorize green "Direct tunnel configuration for Iran server '$tunnel_name' completed."
    colorize green "Iran bridge IP: ${iran_bridge_ip}"
    colorize green "Kharej bridge IP to use: ${kharej_bridge_ip}"
    colorize green "Configured ports: ${input_ports}"
    press_key
    return 0
}

# Function to configure Direct tunnel for Kharej server
function configure_direct_kharej() {
    read -p "[*] Enter tunnel name (e.g., direct-tunnel): " tunnel_name
    tunnel_name=$(echo "$tunnel_name" | tr ' ' '-' | tr -d '[:space:]')
    if [[ -z "$tunnel_name" ]]; then
        colorize red "Tunnel name cannot be empty."
        press_key
        return 1
    fi
    if [[ -f "${CONFIG_DIR}/direct-kharej-${tunnel_name}.conf" ]]; then
        colorize red "Tunnel with name '$tunnel_name' already exists."
        press_key
        return 1
    fi

    echo "Kharej server address type:"
    echo "1) IPv4"
    echo "2) IPv6"
    read -p "Enter choice: " ip_choice
    case $ip_choice in
        1) ip_type="ipv4" ;;
        2) ip_type="ipv6" ;;
        *) colorize red "Invalid option! Defaulting to IPv4"; ip_type="ipv4" ;;
    esac

    if [[ "$ip_type" == "ipv4" ]]; then
        local_ip=$(ip -4 addr show $(detect_network_interface) | grep inet | awk '{print $2}' | cut -d'/' -f1)
    else
        local_ip=$(ip -6 addr show $(detect_network_interface) | grep inet6 | grep global | awk '{print $2}' | cut -d'/' -f1)
    fi
    if [[ -z "$local_ip" ]]; then
        colorize red "Server IP could not be detected."
        press_key
        return 1
    fi
    colorize green "Kharej server address: $local_ip"

    read -p "[*] Enter Iran server IP (IPv4 or [IPv6]): " remote_ip
    [[ -z "$remote_ip" ]] && { colorize red "Server address cannot be empty."; press_key; return 1; }
    if check_ipv6 "$remote_ip"; then
        remote_ip="${remote_ip#[}"
        remote_ip="${remote_ip%]}"
    elif ! check_ipv4 "$remote_ip"; then
        colorize red "Invalid IP address format."
        press_key
        return 1
    fi

    while true; do
        read -p "[*] Enter tunnel port (e.g., 4790): " tunnel_port
        if [[ "$tunnel_port" =~ ^[0-9]+$ ]] && [ "$tunnel_port" -gt 22 ] && [ "$tunnel_port" -le 65535 ]; then
            if check_port "$tunnel_port" "udp"; then
                colorize red "Port $tunnel_port is in use."
            else
                break
            fi
        else
            colorize red "Enter a valid port (23-65535)"
        fi
    done

    network_interface=$(detect_network_interface)
    colorize green "Detected network interface: $network_interface"
        read -p "[*] Enter VXLAN ID (default: 100): " vxlan_id
        [[ -z "$vxlan_id" ]] && vxlan_id=100
        if [[ ! "$vxlan_id" =~ ^[0-9]+$ ]] || [ "$vxlan_id" -lt 1 ] || [ "$vxlan_id" -gt 16777215 ]; then
                colorize red "Invalid VXLAN ID. Must be between 1 and 16777215."
                press_key
                return 1
        fi
    read -p "[*] Enter Kharej bridge IP address (default: 10.0.10.2): " bridge_ip
    [[ -z "$bridge_ip" ]] && bridge_ip="10.0.10.2"
    if [[ ! "$bridge_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        colorize red "Invalid bridge IP address (must be in format 10.0.10.x)."
        press_key
        return 1
    fi
    bridge_ip="${bridge_ip}/24"
    colorize green "Kharej bridge IP: $bridge_ip"

    
    ip link delete "vxlan${vxlan_id}" 2>/dev/null
    ip link delete "br${vxlan_id}" 2>/dev/null
    ip addr flush dev "br${vxlan_id}" 2>/dev/null

    if ! validate_vxlan_setup "$local_ip" "$remote_ip" "$tunnel_port" "$network_interface" "$vxlan_id"; then
        press_key
        return 1
    fi

    ip link add vxlan${vxlan_id} type vxlan id $vxlan_id local "$local_ip" remote "$remote_ip" dstport "$tunnel_port" dev "$network_interface" || {
        colorize red "Failed to create VXLAN interface."
        press_key
        return 1
    }
    ip link add name br${vxlan_id} type bridge || {
        colorize red "Failed to create bridge."
        ip link delete vxlan${vxlan_id} 2>/dev/null
        press_key
        return 1
    }
    ip link set vxlan${vxlan_id} master br${vxlan_id} || {
        colorize red "Failed to attach VXLAN to bridge."
        ip link delete vxlan${vxlan_id} 2>/dev/null
        ip link delete br${vxlan_id} 2>/dev/null
        press_key
        return 1
    }
    ip link set br${vxlan_id} up || {
        colorize red "Failed to bring up bridge."
        ip link delete vxlan${vxlan_id} 2>/dev/null
        ip link delete br${vxlan_id} 2>/dev/null
        press_key
        return 1
    }
    ip link set vxlan${vxlan_id} up || {
        colorize red "Failed to bring up VXLAN."
        ip link delete vxlan${vxlan_id} 2>/dev/null
        ip link delete br${vxlan_id} 2>/dev/null
        press_key
        return 1
    }
    ip addr flush dev br${vxlan_id} 2>/dev/null
    ip addr add "${bridge_ip}" dev br${vxlan_id} || {
        colorize red "Failed to assign IP to bridge."
        ip link delete vxlan${vxlan_id} 2>/dev/null
        ip link delete br${vxlan_id} 2>/dev/null
        press_key
        return 1
    }

    config_file="${CONFIG_DIR}/direct-kharej-${tunnel_name}.conf"
    cat << EOF > "$config_file"
vxlan_id=$vxlan_id
local_ip=$local_ip
remote_ip=$remote_ip
dstport=$tunnel_port
network_interface=$network_interface
bridge_ip=$bridge_ip
EOF

    service_file="${SERVICE_DIR}/RGT-direct-kharej-${tunnel_name}.service"
    cat << EOF > "$service_file"
[Unit]
Description=RGT Direct Kharej Tunnel $tunnel_name
After=network.target

[Service]
Type=oneshot
ExecStart=/bin/bash -c "ip link show vxlan${vxlan_id} >/dev/null 2>&1 || ip link add vxlan${vxlan_id} type vxlan id ${vxlan_id} local $local_ip remote $remote_ip dstport $tunnel_port dev $network_interface; ip link show br${vxlan_id} >/dev/null 2>&1 || ip link add name br${vxlan_id} type bridge; ip link set vxlan${vxlan_id} master br${vxlan_id}; ip link set br${vxlan_id} up; ip link set vxlan${vxlan_id} up; ip addr flush dev br${vxlan_id} 2>/dev/null; ip addr add ${bridge_ip} dev br${vxlan_id}"
ExecStop=/bin/bash -c "ip link delete vxlan${vxlan_id} 2>/dev/null; ip link delete br${vxlan_id} 2>/dev/null"
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload || { colorize red "Failed to reload systemd"; press_key; return 1; }
    systemctl enable "RGT-direct-kharej-${tunnel_name}.service" || { colorize red "Failed to enable service"; press_key; return 1; }
    systemctl start "RGT-direct-kharej-${tunnel_name}.service" || { colorize red "Failed to start service. Check 'systemctl status RGT-direct-kharej-${tunnel_name}.service' for details"; press_key; return 1; }
    colorize green "Direct tunnel configuration for Kharej server '$tunnel_name' completed."
    colorize green "Bridge IP assigned: ${bridge_ip}"
    press_key
    return 0
}

# Function to configure Iran server
function iran_server_configuration() {
    clear
    colorize cyan "Configuring Iran Server" bold
    echo

    read -p "[*] Enter tunnel name (e.g., main-tunnel): " tunnel_name
    tunnel_name=$(echo "$tunnel_name" | tr ' ' '-' | tr -d '[:space:]')
    if [[ -z "$tunnel_name" ]]; then
        colorize red "Tunnel name cannot be empty."
        press_key
        return 1
    fi
    if [[ -f "${CONFIG_DIR}/iran-${tunnel_name}.toml" ]]; then
        colorize red "Tunnel with name '$tunnel_name' already exists."
        press_key
        return 1
    fi

    local_ip="0.0.0.0"
    echo "Iran server address:"
    echo "1) IPv4"
    echo "2) IPv6"
    read -p "Enter choice: " ip_choice
    case $ip_choice in
        1) colorize yellow "IPv4 enabled" ;;
        2) colorize yellow "IPv6 enabled"; local_ip="[::]" ;;
        *) colorize red "Invalid option! Defaulting to IPv4"; local_ip="0.0.0.0" ;;
    esac

    while true; do
        read -p "[*] Enter tunnel port (e.g., 443): " tunnel_port
        if [[ "$tunnel_port" =~ ^[0-9]+$ ]] && [ "$tunnel_port" -gt 22 ] && [ "$tunnel_port" -le 65535 ]; then
            if check_port "$tunnel_port" "tcp"; then
                colorize red "Port $tunnel_port is in use."
            else
                break
            fi
        else
            colorize red "Enter a valid port (23-65535)"
        fi
    done

    local transport=""
    echo "Transport type:"
    echo "1) TCP"
    echo "2) UDP"
    read -p "Enter choice: " transport_choice
    case $transport_choice in
        1) transport="tcp" ;;
        2) transport="udp" ;;
        *) colorize red "Invalid option! Defaulting to TCP"; transport="tcp" ;;
    esac

    local nodelay=""
    read -p "[*] Enable TCP_NODELAY (true/false, press enter for true): " nodelay
    [[ -z "$nodelay" ]] && nodelay="true"
    while [[ "$nodelay" != "true" && "$nodelay" != "false" ]]; do
        read -p "[*] Enable TCP_NODELAY (true/false): " nodelay
        [[ -z "$nodelay" ]] && nodelay="true"
        [[ "$nodelay" != "true" && "$nodelay" != "false" ]] && colorize red "Enter true or false"
    done

    local heartbeat="0"
    colorize yellow "Heartbeat disabled for high connection stability."

    read -p "[-] Security token (press enter for default 'RGT'): " token
    [[ -z "$token" ]] && token="RGT"

    read -p "[*] Enter service ports (e.g., 8008,8080): " input_ports
    input_ports=$(echo "$input_ports" | tr -d ' ')
    IFS=',' read -r -a ports <<< "$input_ports"
    declare -a config_ports
    for port in "${ports[@]}"; do
        if [[ "$port" =~ ^[0-9]+$ ]] && [ "$port" -gt 22 ] && [ "$port" -le 65535 ]; then
            if check_port "$port" "$transport"; then
                colorize red "Port $port is in use."
            else
                config_ports+=("$port")
                colorize green "Port $port added."
            fi
        else
            colorize red "Port $port is invalid. Must be between 23-65535."
        fi
    done
    [[ ${#config_ports[@]} -eq 0 ]] && { colorize red "No valid ports entered. Exiting..."; sleep 2; return 1; }

    config_file="${CONFIG_DIR}/iran-${tunnel_name}.toml"
    cat << EOF > "$config_file"
[server]
bind_addr = "${local_ip}:${tunnel_port}"
default_token = "$token"
heartbeat_interval = $heartbeat

[server.transport]
type = "$transport"

[server.transport.$transport]
nodelay = $nodelay
keepalive_secs = 20
keepalive_interval = 8

EOF

    for port in "${config_ports[@]}"; do
        cat << EOF >> "$config_file"
[server.services.service${port}]
type = "$transport"
token = "$token"
bind_addr = "${local_ip}:${port}"
nodelay = $nodelay

EOF
    done

    service_file="${SERVICE_DIR}/RGT-iran-${tunnel_name}.service"
    cat << EOF > "$service_file"
[Unit]
Description=RGT Iran Tunnel $tunnel_name
After=network.target

[Service]
Type=simple
ExecStart=${RGT_BIN} ${config_file}
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable --now "RGT-iran-${tunnel_name}.service" || { colorize red "Failed to enable service"; return 1; }    colorize green "Iran server configuration for tunnel '$tunnel_name' completed."
    press_key
    return 0
}

# Function to configure Kharej server
function kharej_server_configuration() {
    clear
    colorize cyan "Configuring Kharej Server" bold
    echo

    read -p "[*] Enter tunnel name (e.g., main-tunnel): " tunnel_name
    tunnel_name=$(echo "$tunnel_name" | tr ' ' '-' | tr -d '[:space:]')
    if [[ -z "$tunnel_name" ]]; then
        colorize red "Tunnel name cannot be empty."
        press_key
        return 1
    fi
    if [[ -f "${CONFIG_DIR}/kharej-${tunnel_name}.toml" ]]; then
        colorize red "Tunnel with name '$tunnel_name' already exists."
        press_key
        return 1
    fi

    read -p "[*] Enter Iran server IP (IPv4 or [IPv6]): " server_addr
    [[ -z "$server_addr" ]] && { colorize red "Server address cannot be empty."; press_key; return 1; }
    if check_ipv6 "$server_addr"; then
        server_addr="${server_addr#[}"
        server_addr="${server_addr%]}"
    elif ! check_ipv4 "$server_addr"; then
        colorize red "Invalid IP address format."
        press_key
        return 1
    fi

    while true; do
        read -p "[*] Enter tunnel port (e.g., 443): " tunnel_port
        if [[ "$tunnel_port" =~ ^[0-9]+$ ]] && [ "$tunnel_port" -gt 22 ] && [ "$tunnel_port" -le 65535 ]; then
            break
        else
            colorize red "Enter a valid port (23-65535)"
        fi
    done

    local transport=""
    echo "Transport type:"
    echo "1) TCP"
    echo "2) UDP"
    read -p "Enter choice: " transport_choice
    case $transport_choice in
        1) transport="tcp" ;;
        2) transport="udp" ;;
        *) colorize red "Invalid option! Defaulting to TCP"; transport="tcp" ;;
    esac

    local nodelay=""
    read -p "[*] Enable TCP_NODELAY (true/false, press enter for true): " nodelay
    [[ -z "$nodelay" ]] && nodelay="true"
    while [[ "$nodelay" != "true" && "$nodelay" != "false" ]]; do
        read -p "[*] Enable TCP_NODELAY (true/false): " nodelay
        [[ -z "$nodelay" ]] && nodelay="true"
        [[ "$nodelay" != "true" && "$nodelay" != "false" ]] && colorize red "Enter true or false"
    done

    local heartbeat="0"
    colorize yellow "Heartbeat disabled for high connection stability."

    read -p "[-] Security token (press enter for default 'RGT'): " token
    [[ -z "$token" ]] && token="RGT"

    read -p "[*] Enter service ports (e.g., 8008,8080): " input_ports
    input_ports=$(echo "$input_ports" | tr -d ' ')
    IFS=',' read -r -a ports <<< "$input_ports"
    declare -a config_ports
    for port in "${ports[@]}"; do
        if [[ "$port" =~ ^[0-9]+$ ]] && [ "$port" -gt 22 ] && [ "$port" -le 65535 ]; then
            config_ports+=("$port")
            colorize green "Port $port added."
        else
            colorize red "Port $port is invalid. Must be between 23-65535."
        fi
    done
    [[ ${#config_ports[@]} -eq 0 ]] && { colorize red "No valid ports entered. Exiting..."; sleep 2; return 1; }

    local_ip="127.0.0.1"

    config_file="${CONFIG_DIR}/kharej-${tunnel_name}.toml"
    cat << EOF > "$config_file"
[client]
remote_addr = "${server_addr}:${tunnel_port}"
default_token = "$token"
heartbeat_timeout = $heartbeat

[client.transport]
type = "$transport"

[client.transport.$transport]
nodelay = $nodelay
keepalive_secs = 20
keepalive_interval = 8

EOF

    for port in "${config_ports[@]}"; do
        cat << EOF >> "$config_file"
[client.services.service${port}]
type = "$transport"
token = "$token"
local_addr = "${local_ip}:${port}"
nodelay = $nodelay

EOF
    done

    service_file="${SERVICE_DIR}/RGT-kharej-${tunnel_name}.service"
    cat << EOF > "$service_file"
[Unit]
Description=RGT Kharej Tunnel $tunnel_name
After=network.target

[Service]
Type=simple
ExecStart=${RGT_BIN} ${config_file}
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable --now "RGT-kharej-${tunnel_name}.service" || { colorize red "Failed to enable service"; return 1; }
    colorize green "Kharej server configuration for tunnel '$tunnel_name' completed."
    press_key
    return 0
}

# Function to edit tunnel
function edit_tunnel() {
    local config_path="$1"
    local tunnel_type="$2"
    local tunnel_name=$(basename "${config_path%.toml}" "${config_path%.conf}" | sed 's/iran-//;s/kharej-//;s/direct-iran-//;s/direct-kharej-//')
    clear
    colorize cyan "Editing tunnel $tunnel_name ($tunnel_type)" bold
    echo
    if [[ "$tunnel_type" == "iran" ]]; then
        echo "1) Edit tunnel port"
        echo "2) Edit tunnel service ports"
        echo "3) Edit security token"
        echo "4) Add new ports to tunnel"
    elif [[ "$tunnel_type" == "kharej" ]]; then
        echo "1) Edit tunnel port"
        echo "2) Edit tunnel service ports"
        echo "3) Edit security token"
        echo "4) Add new ports to tunnel"
        echo "5) Edit Iran IP"
    elif [[ "$tunnel_type" == "direct-iran" ]]; then
        echo "1) Edit tunnel port"
        echo "2) Edit remote server IP"
        echo "3) Edit HAProxy ports"
        echo "4) Edit Iran bridge IP"
        echo "5) Edit Kharej bridge IP"
    else
        echo "1) Edit tunnel port"
        echo "2) Edit remote server IP"
        echo "3) Edit Kharej bridge IP"
    fi
    read -p "Enter choice (0 to return): " edit_choice
    case $edit_choice in
        1) edit_tunnel_port "$config_path" "$tunnel_type" "$tunnel_name" ;;
        2) [[ "$tunnel_type" == "direct-iran" || "$tunnel_type" == "direct-kharej" ]] && edit_remote_ip "$config_path" "$tunnel_type" "$tunnel_name" || edit_config_port "$config_path" "$tunnel_type" "$tunnel_name" ;;
        3) [[ "$tunnel_type" == "direct-iran" ]] && edit_haproxy_ports "$config_path" "$tunnel_type" "$tunnel_name" || [[ "$tunnel_type" == "direct-kharej" ]] && edit_kharej_bridge_ip "$config_path" "$tunnel_type" "$tunnel_name" || edit_security_token "$config_path" "$tunnel_type" "$tunnel_name" ;;
        4) [[ "$tunnel_type" == "direct-iran" ]] && edit_iran_bridge_ip "$config_path" "$tunnel_type" "$tunnel_name" || add_new_ports "$config_path" "$tunnel_type" "$tunnel_name" ;;
        5) [[ "$tunnel_type" == "direct-iran" ]] && edit_kharej_bridge_ip "$config_path" "$tunnel_type" "$tunnel_name" || [[ "$tunnel_type" == "kharej" ]] && edit_iran_ip "$config_path" "$tunnel_name" || { colorize red "Invalid option!"; sleep 1; } ;;
        0) return ;;
        *) colorize red "Invalid option!" && sleep 1 ;;
    esac
    service_name="RGT-${tunnel_type}-${tunnel_name}.service"
    systemctl restart "$service_name" || { colorize red "Failed to restart service after edit"; press_key; return 1; }    if [[ "$tunnel_type" == "direct-iran" ]] && [[ -f "/etc/haproxy/haproxy-${tunnel_name}.cfg" ]]; then
        systemctl restart haproxy || { colorize red "Failed to restart HAProxy"; return 1; }
    fi
}

# Function to edit tunnel port
function edit_tunnel_port() {
    local config_path="$1"
    local tunnel_type="$2"
    local tunnel_name="$3"
    while true; do
        read -p "[*] Enter new tunnel port (e.g., 4789): " new_port
        if [[ "$new_port" =~ ^[0-9]+$ ]] && [ "$new_port" -gt 22 ] && [ "$new_port" -le 65535 ]; then
            if [[ "$tunnel_type" == "iran" || "$tunnel_type" == "direct-iran" || "$tunnel_type" == "direct-kharej" ]] && check_port "$new_port" "udp"; then
                colorize red "Port $new_port is in use."
            else
                break
            fi
        else
            colorize red "Enter a valid port (23-65535)"
        fi
    done
    if [[ "$tunnel_type" == "iran" ]]; then
        local_ip=$(grep "bind_addr = " "$config_path" | head -n 1 | cut -d'"' -f2 | cut -d':' -f1)
        sed -i "s/bind_addr = \".*:.*\"/bind_addr = \"${local_ip}:${new_port}\"/" "$config_path" || { colorize red "Failed to update tunnel port"; return 1; }
    elif [[ "$tunnel_type" == "kharej" ]]; then
        server_addr=$(grep "remote_addr = " "$config_path" | cut -d'"' -f2 | cut -d':' -f1)
        sed -i "s/remote_addr = \".*\"/remote_addr = \"${server_addr}:${new_port}\"/" "$config_path" || { colorize red "Failed to update tunnel port"; return 1; }
    else
        sed -i "s/dstport=.*/dstport=$new_port/" "$config_path" || { colorize red "Failed to update tunnel port"; return 1; }
        vxlan_id=$(grep "^vxlan_id=" "$config_path" | cut -d'=' -f2 | tr -d ' ')
        local_ip=$(grep "^local_ip=" "$config_path" | cut -d'=' -f2 | tr -d ' ')
        remote_ip=$(grep "^remote_ip=" "$config_path" | cut -d'=' -f2 | tr -d ' ')
        network_interface=$(grep "^network_interface=" "$config_path" | cut -d'=' -f2 | tr -d ' ')
        bridge_ip=$(grep "^\(iran_bridge_ip\|kharej_bridge_ip\|bridge_ip\)=" "$config_path" | cut -d'=' -f2 | tr -d ' ')
        service_file="${SERVICE_DIR}/RGT-${tunnel_type}-${tunnel_name}.service"
        cat << EOF > "$service_file"
[Unit]
Description=RGT ${tunnel_type} Tunnel $tunnel_name
After=network.target

[Service]
Type=oneshot
ExecStart=/bin/bash -c "ip link show vxlan${vxlan_id} >/dev/null 2>&1 || ip link add vxlan${vxlan_id} type vxlan id ${vxlan_id} local $local_ip remote $remote_ip dstport $new_port dev $network_interface; ip link show br${vxlan_id} >/dev/null 2>&1 || ip link add name br${vxlan_id} type bridge; ip link set vxlan${vxlan_id} master br${vxlan_id}; ip link set br${vxlan_id} up; ip link set vxlan${vxlan_id} up; ip addr flush dev br${vxlan_id} 2>/dev/null; ip addr add ${bridge_ip} dev br${vxlan_id}$([[ "$tunnel_type" == "direct-iran" ]] && echo "; systemctl restart haproxy" || echo "")"
ExecStop=/bin/bash -c "ip link delete vxlan${vxlan_id} 2>/dev/null; ip link delete br${vxlan_id} 2>/dev/null$([[ "$tunnel_type" == "direct-iran" ]] && echo "; systemctl restart haproxy" || echo "")"
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
    fi
    colorize green "Tunnel port updated to $new_port."
    press_key
}

# Function to edit config port
function edit_config_port() {
    local config_path="$1"
    local tunnel_type="$2"
    local tunnel_name=$(basename "${config_path%.toml}" | sed 's/iran-//;s/kharej-//')
    read -p "[*] Enter current service port to edit (e.g., 8008): " old_port
    if ! grep -q "service${old_port}" "$config_path"; then
        colorize red "Service port $old_port not found."
        press_key
        return 1
    fi
    read -p "[*] Enter new service port (e.g., 8080): " new_port
    if [[ "$new_port" =~ ^[0-9]+$ ]] && [ "$new_port" -gt 22 ] && [ "$new_port" -le 65535 ]; then
        if [[ "$tunnel_type" == "iran" ]] && check_port "$new_port" "tcp"; then
            colorize red "Port $new_port is in use."
            press_key
            return 1
        fi
    else
        colorize red "Port $new_port is invalid."
        press_key
        return 1
    fi
    if [[ "$tunnel_type" == "iran" ]]; then
        sed -i "s/\[server\.services\.service${old_port}\]/\[server\.services\.service${new_port}\]/" "$config_path"
        sed -i "s/bind_addr = \".*:${old_port}\"/bind_addr = \"${local_ip}:${new_port}\"/" "$config_path"
    else
        sed -i "s/\[client\.services\.service${old_port}\]/\[client\.services\.service${new_port}\]/" "$config_path"
        sed -i "s/local_addr = \".*:${old_port}\"/local_addr = \"${local_ip}:${new_port}\"/" "$config_path"
    fi
    colorize green "Service port updated from $old_port to $new_port."
    press_key
}

# Function to edit security token
function edit_security_token() {
    local config_path="$1"
    local tunnel_type="$2"
    local tunnel_name=$(basename "${config_path%.toml}" | sed 's/iran-//;s/kharej-//')
    read -p "[*] Enter new security token (press enter for default 'RGT'): " new_token
    [[ -z "$new_token" ]] && new_token="RGT"
    sed -i "s/default_token = \".*\"/default_token = \"$new_token\"/" "$config_path"
    sed -i "s/token = \".*\"/token = \"$new_token\"/" "$config_path"
    colorize green "Security token updated to $new_token."
    press_key
}

# Function to edit remote IP for direct tunnel
function edit_remote_ip() {
    local config_path="$1"
    local tunnel_type="$2"
    local tunnel_name=$(basename "${config_path%.conf}" | sed 's/direct-iran-//;s/direct-kharej-//')
    read -p "[*] Enter new remote server IP (IPv4 or [IPv6]): " new_ip
    [[ -z "$new_ip" ]] && { colorize red "Server address cannot be empty."; press_key; return 1; }
    if check_ipv6 "$new_ip"; then
        new_ip="${new_ip#[}"
        new_ip="${new_ip%]}"
    elif ! check_ipv4 "$new_ip"; then
        colorize red "Invalid IP address format."
        press_key
        return 1
    fi
    sed -i "s/remote_ip=.*/remote_ip=$new_ip/" "$config_path" || { colorize red "Failed to update remote server IP"; return 1; }
    vxlan_id=$(grep "^vxlan_id=" "$config_path" | cut -d'=' -f2 | tr -d ' ')
    local_ip=$(grep "^local_ip=" "$config_path" | cut -d'=' -f2 | tr -d ' ')
    dstport=$(grep "^dstport=" "$config_path" | cut -d'=' -f2 | tr -d ' ')
    network_interface=$(grep "^network_interface=" "$config_path" | cut -d'=' -f2 | tr -d ' ')
    bridge_ip=$(grep "^\(iran_bridge_ip\|kharej_bridge_ip\|bridge_ip\)=" "$config_path" | cut -d'=' -f2 | tr -d ' ')
    service_file="${SERVICE_DIR}/RGT-${tunnel_type}-${tunnel_name}.service"
    cat << EOF > "$service_file"
[Unit]
Description=RGT ${tunnel_type} Tunnel $tunnel_name
After=network.target

[Service]
Type=oneshot
ExecStart=/bin/bash -c "ip link show vxlan${vxlan_id} >/dev/null 2>&1 || ip link add vxlan${vxlan_id} type vxlan id ${vxlan_id} local $local_ip remote $new_ip dstport $dstport dev $network_interface; ip link show br${vxlan_id} >/dev/null 2>&1 || ip link add name br${vxlan_id} type bridge; ip link set vxlan${vxlan_id} master br${vxlan_id}; ip link set br${vxlan_id} up; ip link set vxlan${vxlan_id} up; ip addr flush dev br${vxlan_id} 2>/dev/null; ip addr add ${bridge_ip} dev br${vxlan_id}$([[ "$tunnel_type" == "direct-iran" ]] && echo "; systemctl restart haproxy" || echo "")"
ExecStop=/bin/bash -c "ip link delete vxlan${vxlan_id} 2>/dev/null; ip link delete br${vxlan_id} 2>/dev/null$([[ "$tunnel_type" == "direct-iran" ]] && echo "; systemctl restart haproxy" || echo "")"
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    colorize green "Remote server IP updated to $new_ip."
    press_key
}

# Function to edit HAProxy ports (Iran only)
function edit_haproxy_ports() {
    local config_path="$1"
    local tunnel_type="$2"
    local tunnel_name=$(basename "${config_path%.conf}" | sed 's/direct-iran-//')
    if [[ "$tunnel_type" != "direct-iran" ]]; then
        colorize red "This option is only available for direct Iran tunnels."
        press_key
        return 1
    fi
    read -p "[*] Enter new HAProxy ports (e.g., 8008,8080): " input_ports
    input_ports=$(echo "$input_ports" | tr -d ' ')
    IFS=',' read -r -a ports <<< "$input_ports"
    declare -a config_ports
    for port in "${ports[@]}"; do
        if [[ "$port" =~ ^[0-9]+$ ]] && [ "$port" -gt 22 ] && [ "$port" -le 65535 ]; then
            if check_port "$port" "tcp"; then
                colorize red "Port $port is in use."
            else
                config_ports+=("$port")
                colorize green "Port $port added."
            fi
        else
            colorize red "Port $port is invalid. Must be between 23-65535."
        fi
    done
    [[ ${#config_ports[@]} -eq 0 ]] && { colorize red "No valid ports entered."; sleep 2; return 1; }
    kharej_bridge_ip=$(grep "kharej_bridge_ip" "$config_path" | cut -d'=' -f2 | tr -d ' ')
    haproxy_config="/etc/haproxy/haproxy-${tunnel_name}.cfg"
    cat << EOF > "$haproxy_config"
global
    log /dev/log local0 warning
    maxconn 4096
    user haproxy
    group haproxy
    daemon

defaults
    log global
    mode tcp
    option tcplog
    timeout connect 5000ms
    timeout client 50000ms
    timeout server 50000ms
    timeout check 5000ms

EOF
    for port in "${config_ports[@]}"; do
        cat << EOF >> "$haproxy_config"
frontend vless_frontend_${port}
    bind *:${port}
    mode tcp
    option tcplog
    default_backend vless_backend_${port}

backend vless_backend_${port}
    mode tcp
    option tcp-check
    server RGT_server ${kharej_bridge_ip%/*}:${port} check inter 5000 rise 2 fall 3

EOF
    done
    sed -i "s/ports=.*/ports=${input_ports}/" "$config_path" || { colorize red "Failed to update ports in config"; return 1; }
    colorize green "HAProxy ports updated successfully."
    press_key
}

# Function to edit Iran bridge IP (Iran only)
function edit_iran_bridge_ip() {
    local config_path="$1"
    local tunnel_type="$2"
    local tunnel_name=$(basename "${config_path%.conf}" | sed 's/direct-iran-//')
    read -p "[*] Enter new Iran bridge IP address (default: 10.0.10.1): " new_bridge_ip
    [[ -z "$new_bridge_ip" ]] && new_bridge_ip="10.0.10.1"
    if [[ ! "$new_bridge_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        colorize red "Invalid bridge IP address (must be in format 10.0.10.x)."
        press_key
        return 1
    fi
    new_bridge_ip="${new_bridge_ip}/24"
    sed -i "s/iran_bridge_ip=.*/iran_bridge_ip=$new_bridge_ip/" "$config_path" || { colorize red "Failed to update Iran bridge IP"; return 1; }
    vxlan_id=$(grep "^vxlan_id=" "$config_path" | cut -d'=' -f2 | tr -d ' ')
    local_ip=$(grep "^local_ip=" "$config_path" | cut -d'=' -f2 | tr -d ' ')
    remote_ip=$(grep "^remote_ip=" "$config_path" | cut -d'=' -f2 | tr -d ' ')
    dstport=$(grep "^dstport=" "$config_path" | cut -d'=' -f2 | tr -d ' ')
    network_interface=$(grep "^network_interface=" "$config_path" | cut -d'=' -f2 | tr -d ' ')
    service_file="${SERVICE_DIR}/RGT-${tunnel_type}-${tunnel_name}.service"
    cat << EOF > "$service_file"
[Unit]
Description=RGT ${tunnel_type} Tunnel $tunnel_name
After=network.target

[Service]
Type=oneshot
ExecStart=/bin/bash -c "ip link show vxlan${vxlan_id} >/dev/null 2>&1 || ip link add vxlan${vxlan_id} type vxlan id ${vxlan_id} local $local_ip remote $remote_ip dstport $dstport dev $network_interface; ip link show br${vxlan_id} >/dev/null 2>&1 || ip link add name br${vxlan_id} type bridge; ip link set vxlan${vxlan_id} master br${vxlan_id}; ip link set br${vxlan_id} up; ip link set vxlan${vxlan_id} up; ip addr flush dev br${vxlan_id} 2>/dev/null; ip addr add ${new_bridge_ip} dev br${vxlan_id}; systemctl restart haproxy"
ExecStop=/bin/bash -c "ip link delete vxlan${vxlan_id} 2>/dev/null; ip link delete br${vxlan_id} 2>/dev/null; systemctl restart haproxy"
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    colorize green "Iran bridge IP updated to $new_bridge_ip."
    press_key
}

# Function to edit Kharej bridge IP
function edit_kharej_bridge_ip() {
    local config_path="$1"
    local tunnel_type="$2"
    local tunnel_name=$(basename "${config_path%.conf}" | sed 's/direct-iran-//;s/direct-kharej-//')
    local ip_key="bridge_ip"
    local default_bridge_ip="10.0.10.2"
    if [[ "$tunnel_type" == "direct-iran" ]]; then
        ip_key="kharej_bridge_ip"
        default_bridge_ip="10.0.10.2"
    fi
    read -p "[*] Enter new Kharej bridge IP address (default: $default_bridge_ip): " new_bridge_ip
    [[ -z "$new_bridge_ip" ]] && new_bridge_ip="$default_bridge_ip"
    if [[ ! "$new_bridge_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        colorize red "Invalid bridge IP address (must be in format 10.0.10.x)."
        press_key
        return 1
    fi
    new_bridge_ip="${new_bridge_ip}/24"
    sed -i "s/${ip_key}=.*/${ip_key}=$new_bridge_ip/" "$config_path" || { colorize red "Failed to update Kharej bridge IP"; return 1; }
    vxlan_id=$(grep "^vxlan_id=" "$config_path" | cut -d'=' -f2 | tr -d ' ')
    local_ip=$(grep "^local_ip=" "$config_path" | cut -d'=' -f2 | tr -d ' ')
    remote_ip=$(grep "^remote_ip=" "$config_path" | cut -d'=' -f2 | tr -d ' ')
    dstport=$(grep "^dstport=" "$config_path" | cut -d'=' -f2 | tr -d ' ')
    network_interface=$(grep "^network_interface=" "$config_path" | cut -d'=' -f2 | tr -d ' ')
    service_file="${SERVICE_DIR}/RGT-${tunnel_type}-${tunnel_name}.service"
    cat << EOF > "$service_file"
[Unit]
Description=RGT ${tunnel_type} Tunnel $tunnel_name
After=network.target

[Service]
Type=oneshot
ExecStart=/bin/bash -c "ip link show vxlan${vxlan_id} >/dev/null 2>&1 || ip link add vxlan${vxlan_id} type vxlan id ${vxlan_id} local $local_ip remote $remote_ip dstport $dstport dev $network_interface; ip link show br${vxlan_id} >/dev/null 2>&1 || ip link add name br${vxlan_id} type bridge; ip link set vxlan${vxlan_id} master br${vxlan_id}; ip link set br${vxlan_id} up; ip link set vxlan${vxlan_id} up; ip addr flush dev br${vxlan_id} 2>/dev/null; ip addr add ${new_bridge_ip} dev br${vxlan_id}$([[ "$tunnel_type" == "direct-iran" ]] && echo "; systemctl restart haproxy" || echo "")"
ExecStop=/bin/bash -c "ip link delete vxlan${vxlan_id} 2>/dev/null; ip link delete br${vxlan_id} 2>/dev/null$([[ "$tunnel_type" == "direct-iran" ]] && echo "; systemctl restart haproxy" || echo "")"
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    colorize green "Kharej bridge IP updated to $new_bridge_ip."
    if [[ "$tunnel_type" == "direct-iran" ]]; then
        haproxy_config="/etc/haproxy/haproxy-${tunnel_name}.cfg"
        if [[ -f "$haproxy_config" ]]; then
            sed -i "s/server RGT_server .*:.* check/server RGT_server ${new_bridge_ip%/*}:%PORT% check/" "$haproxy_config" || { colorize red "Failed to update HAProxy config"; return 1; }
            systemctl restart haproxy || { colorize red "Failed to restart HAProxy"; return 1; }
        fi
    fi
    press_key
}

# Function to add new ports
function add_new_ports() {
    local config_path="$1"
    local tunnel_type="$2"
    local tunnel_name=$(basename "${config_path%.toml}" | sed 's/iran-//;s/kharej-//')
    read -p "[*] Enter new service ports to add (e.g., 8081,8082): " input_ports
    input_ports=$(echo "$input_ports" | tr -d ' ')
    IFS=',' read -r -a ports <<< "$input_ports"
    declare -a config_ports
    for port in "${ports[@]}"; do
        if [[ "$port" =~ ^[0-9]+$ ]] && [ "$port" -gt 22 ] && [ "$port" -le 65535 ]; then
            if check_port "$port" "tcp"; then
                colorize red "Port $port is in use."
            else
                config_ports+=("$port")
                colorize green "Port $port added."
            fi
        else
            colorize red "Port $port is invalid. Must be between 23-65535."
        fi
    done
    [[ ${#config_ports[@]} -eq 0 ]] && { colorize red "No valid ports added."; sleep 2; return 1; }
    transport=$(grep "type = " "$config_path" | head -n 1 | cut -d'"' -f2)
    token=$(grep "default_token = " "$config_path" | cut -d'"' -f2)
    nodelay=$(grep "nodelay = " "$config_path" | head -n 1 | cut -d'=' -f2 | tr -d ' ')
    if [[ "$tunnel_type" == "iran" ]]; then
        local_ip=$(grep "bind_addr = " "$config_path" | head -n 1 | cut -d'"' -f2 | cut -d':' -f1)
        for port in "${config_ports[@]}"; do
            cat << EOF >> "$config_path"
[server.services.service${port}]
type = "$transport"
token = "$token"
bind_addr = "${local_ip}:${port}"
nodelay = $nodelay

EOF
        done
    else
        local_ip=$(grep "local_addr = " "$config_path" | head -n 1 | cut -d'"' -f2 | cut -d':' -f1)
        for port in "${config_ports[@]}"; do
            cat << EOF >> "$config_path"
[client.services.service${port}]
type = "$transport"
token = "$token"
local_addr = "${local_ip}:${port}"
nodelay = $nodelay

EOF
        done
    fi
    colorize green "New ports added successfully."
    press_key
}

# Function to edit Iran IP (Kharej only)
function edit_iran_ip() {
    local config_path="$1"
    local tunnel_name=$(basename "${config_path%.toml}" | sed 's/kharej-//')
    read -p "[*] Enter new Iran server IP (IPv4 or [IPv6]): " new_ip
    [[ -z "$new_ip" ]] && { colorize red "Server address cannot be empty."; press_key; return 1; }
    if check_ipv6 "$new_ip"; then
        new_ip="${new_ip#[}"
        new_ip="${new_ip%]}"
    elif ! check_ipv4 "$new_ip"; then
        colorize red "Invalid IP address format."
        press_key
        return 1
    fi
    tunnel_port=$(grep "remote_addr = " "$config_path" | cut -d':' -f2 | cut -d'"' -f1)
    sed -i "s/remote_addr = \".*\"/remote_addr = \"${new_ip}:${tunnel_port}\"/" "$config_path" || { colorize red "Failed to update Iran server IP"; return 1; }
    colorize green "Iran server IP updated to $new_ip."
    press_key
}

# Function to manage tunnels
function manage_tunnel() {
    clear
    local tunnel_found=0
    colorize cyan "List of existing tunnels:" bold
    echo
    local index=1
    declare -a configs
    declare -a config_types
    declare -a tunnel_names
    declare -a service_names

    # Function to check tunnel status
    check_tunnel_status() {
        local service_name="$1"
        local tunnel_type="$2"
        local tunnel_name="$3"
        # Check if service is not active
        if ! systemctl is-active "$service_name" &> /dev/null; then
            return 1
        fi
        # Check for HAProxy errors for direct-iran tunnels
        if [[ "$tunnel_type" == "direct-iran" ]]; then
            local ports=$(grep "^ports=" "${CONFIG_DIR}/direct-iran-${tunnel_name}.conf" 2>/dev/null | cut -d'=' -f2 | tr -d ' ')
            IFS=',' read -r -a port_array <<< "$ports"
            for port in "${port_array[@]}"; do
                if journalctl -u haproxy -n 100 --no-pager | grep -q "backend RGT_backend_${port}.*no server available"; then
                    return 1
                fi
            done
        fi
        return 0
    }

    # List Direct Iran tunnels
    for config_path in "$CONFIG_DIR"/direct-iran-*.conf; do
        if [[ -f "$config_path" ]]; then
            tunnel_found=1
            tunnel_name=$(basename "$config_path" .conf | sed 's/^direct-iran-//')
            tunnel_type="direct-iran"
            service_name="RGT-direct-iran-${tunnel_name}.service"
            tunnel_port=$(grep "^dstport=" "$config_path" 2>/dev/null | cut -d'=' -f2 | tr -d ' ')
            config_ports=$(grep "^ports=" "$config_path" 2>/dev/null | cut -d'=' -f2 | tr -d ' ')
            bridge_ip=$(grep "^kharej_bridge_ip=" "$config_path" 2>/dev/null | cut -d'=' -f2 | tr -d ' ')
            [[ -z "$tunnel_port" ]] && tunnel_port="Unknown"
            [[ -z "$config_ports" ]] && config_ports="None"
            [[ -z "$bridge_ip" ]] && bridge_ip="10.0.10.1/24"
            configs+=("$config_path")
            config_types+=("$tunnel_type")
            tunnel_names+=("$tunnel_name")
            service_names+=("$service_name")
            if check_tunnel_status "$service_name" "$tunnel_type" "$tunnel_name"; then
                echo -e "${CYAN}${index}${NC}) ${GREEN}Direct Iran Tunnel ${tunnel_name}${NC} (Tunnel Port: ${YELLOW}${tunnel_port}${NC}, HAProxy Ports: ${YELLOW}${config_ports}${NC}, Bridge IP: ${YELLOW}${bridge_ip}${NC})"
            else
                echo -e "${CYAN}${index}${NC}) ${RED}Direct Iran Tunnel ${tunnel_name}${NC} (Tunnel Port: ${YELLOW}${tunnel_port}${NC}, HAProxy Ports: ${YELLOW}${config_ports}${NC}, Bridge IP: ${YELLOW}${bridge_ip}${NC})"
            fi
            ((index++))
        fi
    done

    # List Direct Kharej tunnels
    for config_path in "$CONFIG_DIR"/direct-kharej-*.conf; do
        if [[ -f "$config_path" ]]; then
            tunnel_found=1
            tunnel_name=$(basename "$config_path" .conf | sed 's/^direct-kharej-//')
            tunnel_type="direct-kharej"
            service_name="RGT-direct-kharej-${tunnel_name}.service"
            tunnel_port=$(grep "^dstport=" "$config_path" 2>/dev/null | cut -d'=' -f2 | tr -d ' ')
            bridge_ip=$(grep "^bridge_ip=" "$config_path" 2>/dev/null | cut -d'=' -f2 | tr -d ' ')
            [[ -z "$tunnel_port" ]] && tunnel_port="Unknown"
            [[ -z "$bridge_ip" ]] && bridge_ip="10.0.10.2/24"
            configs+=("$config_path")
            config_types+=("$tunnel_type")
            tunnel_names+=("$tunnel_name")
            service_names+=("$service_name")
            if check_tunnel_status "$service_name" "$tunnel_type" "$tunnel_name"; then
                echo -e "${CYAN}${index}${NC}) ${GREEN}Direct Kharej Tunnel ${tunnel_name}${NC} (Tunnel Port: ${YELLOW}${tunnel_port}${NC}, Bridge IP: ${YELLOW}${bridge_ip}${NC})"
            else
                echo -e "${CYAN}${index}${NC}) ${RED}Direct Kharej Tunnel ${tunnel_name}${NC} (Tunnel Port: ${YELLOW}${tunnel_port}${NC}, Bridge IP: ${YELLOW}${bridge_ip}${NC})"
            fi
            ((index++))
        fi
    done

    # List Iran tunnels (Reverse)
    for config_path in "$CONFIG_DIR"/iran-*.toml; do
        if [[ -f "$config_path" ]]; then
            tunnel_found=1
            tunnel_name=$(basename "$config_path" .toml | sed 's/^iran-//')
            tunnel_type="iran"
            service_name="RGT-iran-${tunnel_name}.service"
            tunnel_port=$(grep "bind_addr" "$config_path" 2>/dev/null | head -n 1 | cut -d':' -f2 | cut -d'"' -f1)
            config_ports=$(grep "bind_addr.*:[0-9]" "$config_path" 2>/dev/null | grep -v "bind_addr.*:${tunnel_port}" | cut -d':' -f2 | cut -d'"' -f1 | tr '\n' ',' | sed 's/,$//')
            [[ -z "$tunnel_port" ]] && tunnel_port="Unknown"
            [[ -z "$config_ports" ]] && config_ports="None"
            configs+=("$config_path")
            config_types+=("$tunnel_type")
            tunnel_names+=("$tunnel_name")
            service_names+=("$service_name")
            if check_tunnel_status "$service_name" "$tunnel_type" "$tunnel_name"; then
                echo -e "${CYAN}${index}${NC}) ${GREEN}Iran Tunnel ${tunnel_name}${NC} (Tunnel Port: ${YELLOW}${tunnel_port}${NC}, Service Ports: ${YELLOW}${config_ports}${NC})"
            else
                echo -e "${CYAN}${index}${NC}) ${RED}Iran Tunnel ${tunnel_name}${NC} (Tunnel Port: ${YELLOW}${tunnel_port}${NC}, Service Ports: ${YELLOW}${config_ports}${NC})"
            fi
            ((index++))
        fi
    done

    # List Kharej tunnels (Reverse)
    for config_path in "$CONFIG_DIR"/kharej-*.toml; do
        if [[ -f "$config_path" ]]; then
            tunnel_found=1
            tunnel_name=$(basename "$config_path" .toml | sed 's/^kharej-//')
            tunnel_type="kharej"
            service_name="RGT-kharej-${tunnel_name}.service"
            tunnel_port=$(grep "remote_addr" "$config_path" 2>/dev/null | cut -d':' -f2 | cut -d'"' -f1)
            config_ports=$(grep "local_addr" "$config_path" 2>/dev/null | cut -d':' -f2 | cut -d'"' -f1 | tr '\n' ',' | sed 's/,$//')
            [[ -z "$tunnel_port" ]] && tunnel_port="Unknown"
            [[ -z "$config_ports" ]] && config_ports="None"
            configs+=("$config_path")
            config_types+=("$tunnel_type")
            tunnel_names+=("$tunnel_name")
            service_names+=("$service_name")
            if check_tunnel_status "$service_name" "$tunnel_type" "$tunnel_name"; then
                echo -e "${CYAN}${index}${NC}) ${GREEN}Kharej Tunnel ${tunnel_name}${NC} (Tunnel Port: ${YELLOW}${tunnel_port}${NC}, Service Ports: ${YELLOW}${config_ports}${NC})"
            else
                echo -e "${CYAN}${index}${NC}) ${RED}Kharej Tunnel ${tunnel_name}${NC} (Tunnel Port: ${YELLOW}${tunnel_port}${NC}, Service Ports: ${YELLOW}${config_ports}${NC})"
            fi
            ((index++))
        fi
    done

    echo
    if [[ $tunnel_found -eq 0 ]]; then
        colorize red "No tunnels found." bold
        press_key
        return 1
    fi

    read -p "Enter choice (0 to return): " choice
    [[ "$choice" == "0" ]] && return
    while ! [[ "$choice" =~ ^[0-9]+$ ]] || (( choice < 1 || choice >= index )); do
        colorize red "Invalid choice. Enter a number between 1 and $((index-1)) or 0 to return."
        read -p "Enter choice: " choice
        [[ "$choice" == "0" ]] && return
    done

    # Get selected tunnel details
    selected_config="${configs[$((choice - 1))]}"
    tunnel_type="${config_types[$((choice - 1))]}"
    tunnel_name="${tunnel_names[$((choice - 1))]}"
    service_name="${service_names[$((choice - 1))]}"
    service_path="${SERVICE_DIR}/${service_name}"

    # Verify config and service files
    if [[ ! -f "$selected_config" ]]; then
        colorize red "Config file $selected_config not found. Please check configuration."
        press_key
        return 1
    fi
    if [[ ! -f "$service_path" ]]; then
        colorize red "Service file $service_path not found. Please check configuration."
        press_key
        return 1
    fi

    # Check for consecutive errors
    check_consecutive_errors "$service_name"

    echo
    colorize cyan "Manage Tunnel: $tunnel_name ($tunnel_type)" bold
    echo "1) Start tunnel"
    echo "2) Stop tunnel"
    echo "3) Restart tunnel"
    echo "4) Check tunnel status"
    echo "5) Edit tunnel configuration"
    echo "6) Delete tunnel"
    read -p "Enter choice (0 to return): " manage_choice

    case $manage_choice in
        1)
            systemctl start "$service_name"
            if [[ $? -eq 0 ]]; then
                colorize green "Tunnel $tunnel_name started successfully."
            else
                colorize red "Failed to start tunnel $tunnel_name. Check 'systemctl status $service_name' for details."
            fi
            if [[ "$tunnel_type" == "direct-iran" || "$tunnel_type" == "direct-kharej" ]]; then
                systemctl restart haproxy
                if [[ $? -eq 0 ]]; then
                    colorize green "HAProxy restarted successfully."
                else
                    colorize red "Failed to restart HAProxy."
                fi
            fi
            ;;
        2)
            systemctl stop "$service_name"
            if [[ $? -eq 0 ]]; then
                colorize green "Tunnel $tunnel_name stopped successfully."
            else
                colorize red "Failed to stop tunnel $tunnel_name. Check 'systemctl status $service_name' for details."            fi
            if [[ "$tunnel_type" == "direct-iran" || "$tunnel_type" == "direct-kharej" ]]; then
                systemctl restart haproxy
                if [[ $? -eq 0 ]]; then
                    colorize green "HAProxy restarted successfully."
                else
                    colorize red "Failed to restart HAProxy."
                fi
            fi
            ;;
        3)
            systemctl restart "$service_name"
            if [[ $? -eq 0 ]]; then
                colorize green "Tunnel $tunnel_name restarted successfully."
            else
                colorize red "Failed to restart tunnel $tunnel_name. Check 'systemctl status $service_name' for details."
            fi
            if [[ "$tunnel_type" == "direct-iran" || "$tunnel_type" == "direct-kharej" ]]; then
                systemctl restart haproxy
                if [[ $? -eq 0 ]]; then
                    colorize green "HAProxy restarted successfully."
                else
                    colorize red "Failed to restart HAProxy."
                fi
            fi
            ;;
        4)
            systemctl status "$service_name"
            if [[ "$tunnel_type" == "direct-iran" || "$tunnel_type" == "direct-kharej" ]]; then
                systemctl status haproxy
            fi
            ;;
        5)
            edit_tunnel "$selected_config" "$tunnel_type" "$tunnel_name"
            ;;
        6)
            read -p "Are you sure you want to delete tunnel $tunnel_name? (y/n): " confirm
            if [[ "$confirm" == "y" || "$confirm" == "Y" ]]; then
                destroy_tunnel "$selected_config" "$tunnel_type"
            else
                colorize yellow "Tunnel deletion canceled."
            fi
            ;;
        0)
            return
            ;;
        *)
            colorize red "Invalid option!"
            ;;
    esac
}

function destroy_tunnel() {
    local config_path="$1"
    local tunnel_type="$2"
    tunnel_name=$(basename "${config_path%.toml}" "${config_path%.conf}" | sed 's/iran-//;s/kharej-//;s/direct-iran-//;s/direct-kharej-//')
    service_name="RGT-${tunnel_type}-${tunnel_name}.service"
    service_path="/etc/systemd/system/${service_name}"
    HAPROXY_CFG="/etc/haproxy/haproxy.cfg"

    # Check if config file exists
    if [[ ! -f "$config_path" ]]; then
        colorize red "Config file $config_path not found."
        press_key
        return 1
    fi

    # Stop and disable the service if active or enabled
    if systemctl is-active "$service_name" &> /dev/null; then
        systemctl stop "$service_name" || { colorize yellow "Failed to stop service $service_name."; press_key; return 1; }
    fi
    if systemctl is-enabled "$service_name" &> /dev/null; then
        systemctl disable "$service_name" || { colorize yellow "Failed to disable service $service_name."; press_key; return 1; }
    fi

    # Remove the service file
    rm -f "$service_path" || { colorize yellow "Failed to remove service file $service_path."; press_key; return 1; }
    systemctl daemon-reload || { colorize yellow "Failed to reload systemd."; press_key; return 1; }

    # Clean up VXLAN and bridge interfaces for direct tunnels
    if [[ "$tunnel_type" == "direct-iran" || "$tunnel_type" == "direct-kharej" ]]; then
        vxlan_id=$(grep "^vxlan_id=" "$config_path" 2>/dev/null | cut -d'=' -f2 | tr -d ' ')
        if [[ -n "$vxlan_id" ]]; then
            ip link delete "vxlan${vxlan_id}" 2>/dev/null || colorize yellow "Failed to delete VXLAN interface vxlan${vxlan_id}."
            ip link delete "br${vxlan_id}" 2>/dev/null || colorize yellow "Failed to delete bridge interface br${vxlan_id}."
        fi
        # Remove HAProxy configuration file completely for direct-iran tunnels
        if [[ "$tunnel_type" == "direct-iran" ]]; then
            if [[ -f "$HAPROXY_CFG" ]]; then
                rm -f "$HAPROXY_CFG" || { colorize yellow "Failed to remove HAProxy configuration file."; press_key; return 1; }
                colorize green "HAProxy configuration file removed."
            fi
            # Stop and disable HAProxy
            systemctl stop haproxy &> /dev/null
            systemctl disable haproxy &> /dev/null
            colorize green "HAProxy service stopped and disabled."
        fi
    fi

    # Remove the configuration file
    rm -f "$config_path" || { colorize yellow "Failed to remove config file $config_path."; press_key; return 1; }

    # Clear systemd journal to remove old broadcast messages
    journalctl --vacuum-time=1s &> /dev/null

    colorize green "Tunnel $tunnel_name deleted successfully."
    press_key
    return 0
}

# Function to restart service
function restart_service() {
    local service_name="$1"
    colorize yellow "Restarting $service_name..." bold
    if systemctl list-units --type=service | grep -q "$service_name"; then
        systemctl restart "$service_name" || colorize red "Failed to restart service $service_name."
        if [[ "$service_name" =~ direct-iran || "$service_name" =~ direct-kharej ]]; then
            systemctl restart haproxy || colorize red "Failed to restart HAProxy."
        fi
        colorize green "Tunnel restarted successfully."
    else
        colorize red "Tunnel $service_name not found."
    fi
    press_key
}

# Function to view tunnel logs
view_tunnel_logs() {
    clear
    journalctl -u "$1" --no-pager
    press_key
}

# Function to view tunnel status
view_tunnel_status() {
    clear
    systemctl status "$1"
    press_key
}

# Function to remove rgt core
function remove_core() {
    clear
    if ls "$CONFIG_DIR"/*.toml "$CONFIG_DIR"/*.conf &> /dev/null; then
        colorize red "Remove all tunnels before removing RGT core."
        press_key
        return 1
    fi
    read -p "Confirm removal of RGT core? (y/n): " confirm
    if [[ "$confirm" =~ ^[yY]$ ]]; then
        for vxlan in $(ip link show | grep -oP 'vxlan\d+'); do
            ip link delete "$vxlan" 2>/dev/null || colorize yellow "Failed to delete VXLAN interface $vxlan."
        done
        for bridge in $(ip link show | grep -oP 'br\d+'); do
            ip link delete "$bridge" 2>/dev/null || colorize yellow "Failed to delete bridge interface $bridge."
        done
        for service in $(ls "$SERVICE_DIR"/RGT-*.service 2>/dev/null); do
            service_name=$(basename "$service")
            systemctl stop "$service_name" 2>/dev/null
            systemctl disable "$service_name" 2>/dev/null
            rm -f "$service" || colorize yellow "Failed to remove service file $service."
        done
        rm -f /etc/haproxy/haproxy-*.cfg 2>/dev/null || colorize yellow "Failed to remove HAProxy configs."
        systemctl restart haproxy 2>/dev/null || colorize yellow "Failed to restart HAProxy."
        rm -rf "$CONFIG_DIR" || colorize yellow "Failed to remove RGT core directory $CONFIG_DIR."
        systemctl daemon-reload
        colorize green "RGT core removed."
    else
        colorize yellow "Removal canceled."
    fi
    press_key
}
# Function to display logo
function display_logo() {
    echo -e "${CYAN}"
    cat << "EOF"
██████╗  ██████╗ ████████╗
██╔══██╗██╔═══╗╚╗   ██╔══╝
██████╔╝██║█████║   ██║   RGT Tunnel
██╔╗██║ ██║   ██║   ██║   (by @Coderman_ir)
██║║██║ ╚██████╔╝   ██║
╚═╝╚==╝  ╚═════╝    ╚═╝
-----------------------------------
EOF
}

# Function to display server info
function display_server_info() {
    SERVER_IP=$(hostname -I | awk '{print $1}')
    echo -e "${CYAN}IP Address:${NC} $SERVER_IP"
    if [[ -f "${RGT_BIN}" ]]; then
        echo -e "${CYAN}Core Installed:${NC} ${GREEN}Yes${NC}"
    else
        echo -e "${CYAN}Core Installed:${NC} ${RED}No${NC}"
    fi
    echo -e "${YELLOW}-----------------------------------${NC}"
}

# Function to display menu
function display_menu() {
    clear
    display_logo
    echo -e "${CYAN}Version: ${YELLOW}1.0${NC}"
    echo -e "${CYAN}GitHub: ${YELLOW}github.com/black-sec/RGT${NC}"
    display_server_info
    echo
    colorize green "1) Setup new tunnel" bold
    colorize green "2) Manage tunnels" bold
    colorize green "3) Install RGT core" bold
    colorize red "4) Uninstall RGT core" bold
    colorize yellow "5) Update script" bold
    colorize cyan "6) RGT tools" bold
    colorize yellow "7) Exit" bold
    echo
}

# Main loop
install_dependencies
mkdir -p "$CONFIG_DIR"
if [[ ! -f "${SCRIPT_PATH}" ]]; then
    cp "$0" "${SCRIPT_PATH}"
    chmod +x "${SCRIPT_PATH}"
    colorize green "Script is now executable as 'RGT' command." bold
fi
while true; do
    display_menu
    read -p "Enter a choice: " choice
    case $choice in
        1)
            clear
            colorize cyan "Select tunnel type:" bold
            echo "1) Direct"
            echo "2) Reverse"
            read -p "Enter choice: " tunnel_type
            case $tunnel_type in
                1)
                    direct_server_configuration
                    ;;
                2)
                    clear
                    colorize cyan "Select server location:" bold
                    echo "1) Iran Server"
                    echo "2) Kharej Server"
                    read -p "Enter choice: " server_type
                    case $server_type in
                        1) iran_server_configuration ;;
                        2) kharej_server_configuration ;;
                        *) colorize red "Invalid option!" && sleep 1 ;;
                    esac
                    ;;
                *) colorize red "Invalid option!" && sleep 1 ;;
            esac
            ;;
        2) manage_tunnel ;;
        3) download_and_extract_rgt ;;
        4) remove_core ;;
        5) update_script ;;
        6) rgt_tools ;;
        7) exit 0 ;;
        *) colorize red "Invalid option!" && sleep 1 ;;
    esac
done
