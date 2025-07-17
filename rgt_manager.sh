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
press_key() {
    read -p "Press any key to continue..."
}

# Function to colorize text
colorize() {
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

# Function to install dependencies
install_dependencies() {
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
}

# Function to display manual download instructions
manual_download_instructions() {
    colorize red "Failed to download RGT core from GitHub due to possible network restrictions."
    echo
    colorize yellow "Please follow these steps to manually download and install the RGT core:"
    echo
    echo "1. Download the file 'RGT-x86-64-linux.zip' from:"
    echo
    colorize yellow "   https://github.com/black-sec/RGT/raw/main/core/RGT-x86-64-linux.zip"
    echo
    echo "   You can use a browser or a tool like 'wget' on a system with access:"
    echo "   wget https://github.com/black-sec/RGT/raw/main/core/RGT-x86-64-linux.zip"
    echo
    echo "2. Upload the downloaded file to the server /root/ using SFTP:"
    echo
    echo "3. Log in to the server via SSH and extract the file:"
    echo
    echo "   mkdir -p /root/rgt-core"
    echo "   unzip /root/RGT-x86-64-linux.zip -d /root/rgt-core"
    echo "   mv /root/rgt-core/rgt /root/rgt-core/rgt"
    echo "   chmod +x /root/rgt-core/rgt"
    echo "   rm /root/RGT-x86-64-linux.zip"
    echo
    echo "4. Run this script again to continue configuration."
    press_key
    exit 1
}

# Function to validate downloaded zip file
validate_zip_file() {
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
        colorize red "Downloaded file is too small to be valid."
        return 1
    fi
    return 0
}

# Function to download and install rgt
download_and_extract_rgt() {
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
    colorize green "RGT installation completed." bold
    # Make script executable as 'RGT' command
    cp "$0" "${SCRIPT_PATH}"
    chmod +x "${SCRIPT_PATH}"
    colorize green "Script is now executable as 'RGT' command." bold
}

# Function to update script
update_script() {
    clear
    colorize cyan "Updating RGT Manager Script" bold
    echo
    UPDATE_URL="https://github.com/black-sec/RGT/raw/main/rgt_manager.sh"
    TEMP_SCRIPT="/tmp/rgt_manager.sh"
    colorize yellow "Downloading updated script..."
    if ! curl -sSL -o "$TEMP_SCRIPT" "$UPDATE_URL"; then
        colorize red "Failed to download updated script. Please check your network or the URL."
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
    colorize yellow "Please run the script again with 'RGT' to use the updated version."
    press_key
    exit 0
}

# Function to check if a port is in use
check_port() {
    local port=$1
    local transport=$2
    if [[ "$transport" == "tcp" ]]; then
        ss -tlnp "sport = :$port" | grep "$port" &> /dev/null && return 0 || return 1
    elif [[ "$transport" == "udp" ]]; then
        ss -ulnp "sport = :$port" | grep "$port" &> /dev/null && return 0 || return 1
    else
        return 1
    fi
}

# Function to validate IPv6 address
check_ipv6() {
    local ip=$1
    ip="${ip#[}"
    ip="${ip%]}"
    ipv6_pattern="^([0-9a-fA-F]{1,4}:){7}([0-9a-fA-F]{1,4}|:)$|^(([0-9a-fA-F]{1,4}:){1,7}|:):((:[0-9a-fA-F]{1,4}){1,7}|:)$"
    [[ $ip =~ $ipv6_pattern ]] && return 0 || return 1
}

# Function to check for consecutive errors and restart
check_consecutive_errors() {
    local service_name="$1"
    local tunnel_name=$(echo "$service_name" | sed 's/RGT-iran-//;s/RGT-kharej-//;s/.service//')
    local logs=$(journalctl -u "$service_name" -n 50 --no-pager | tail -n 2)
    local error_count=$(echo "$logs" | grep -c "ERROR")
    if [[ $error_count -ge 2 ]]; then
        colorize yellow "Detected two consecutive errors in $service_name logs. Restarting..."
        systemctl restart "$service_name"
        if [[ $? -eq 0 ]]; then
            colorize green "Tunnel $tunnel_name restarted successfully due to consecutive errors."
        else
            colorize red "Failed to restart tunnel $tunnel_name."
        fi
    fi
}

# Function to configure Iran server
iran_server_configuration() {
    clear
    colorize cyan "Configuring Iran server" bold
    echo

    # Tunnel name
    read -p "[*] Enter Tunnel Name (e.g., main-tunnel): " tunnel_name
    tunnel_name=$(echo "$tunnel_name" | tr ' ' '-' | tr -d '[:space:]')
    if [[ -z "$tunnel_name" ]]; then
        colorize red "Tunnel name cannot be empty."
        press_key
        return 1
    fi
    if [[ -f "${CONFIG_DIR}/iran-${tunnel_name}.toml" ]]; then
        colorize red "Tunnel name '$tunnel_name' already exists."
        press_key
        return 1
    fi

    # IPv4/IPv6 selection
    local_ip="0.0.0.0"
    echo "Iran server address:"
    echo "1) IPv4"
    echo "2) IPv6"
    read -p "Enter choice: " ip_choice
    case $ip_choice in
        1) colorize yellow "IPv4 Enabled" ;;
        2) colorize yellow "IPv6 Enabled"; local_ip="[::]" ;;
        *) colorize red "Invalid option! Defaulting to IPv4"; local_ip="0.0.0.0" ;;
    esac

    # Tunnel port
    while true; do
        read -p "[*] Tunnel port (e.g., 443): " tunnel_port
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

    # Transport type
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

    # TCP_NODELAY
    local nodelay=""
    read -p "[*] Enable TCP_NODELAY (true/false, press enter for true): " nodelay
    [[ -z "$nodelay" ]] && nodelay="true"
    while [[ "$nodelay" != "true" && "$nodelay" != "false" ]]; do
        read -p "[*] Enable TCP_NODELAY (true/false): " nodelay
        [[ -z "$nodelay" ]] && nodelay="true"
        [[ "$nodelay" != "true" && "$nodelay" != "false" ]] && colorize red "Enter true or false"
    done

    # Heartbeat
    local heartbeat="0"
    colorize yellow "Heartbeat disabled for high connection stability."

    # Token
    read -p "[-] Security Token (press enter for default 'RGT'): " token
    [[ -z "$token" ]] && token="RGT"

    # Service ports
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
            colorize red "Invalid port $port. Must be 23-65535."
        fi
    done
    [[ ${#config_ports[@]} -eq 0 ]] && { colorize red "No valid ports entered. Exiting."; sleep 2; return 1; }

    # Generate server config
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

    # Create systemd service
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
    systemctl enable --now "RGT-iran-${tunnel_name}.service" || { colorize red "Failed to enable service"; return 1; }
    colorize green "Iran server configuration completed for tunnel '$tunnel_name'."
}

# Function to configure Kharej server
kharej_server_configuration() {
    clear
    colorize cyan "Configuring Kharej server" bold
    echo

    # Tunnel name
    read -p "[*] Enter Tunnel Name (e.g., main-tunnel): " tunnel_name
    tunnel_name=$(echo "$tunnel_name" | tr ' ' '-' | tr -d '[:space:]')
    if [[ -z "$tunnel_name" ]]; then
        colorize red "Tunnel name cannot be empty."
        press_key
        return 1
    fi
    if [[ -f "${CONFIG_DIR}/kharej-${tunnel_name}.toml" ]]; then
        colorize red "Tunnel name '$tunnel_name' already exists."
        press_key
        return 1
    fi

    # Server address
    echo "Iran server address:"
    echo "1) IPv4"
    echo "2) IPv6"
    read -p "Enter choice: " ip_choice
    case $ip_choice in
        1)
            read -p "[*] Enter Iran IPv4 address (e.g., 85.9.102.245): " server_addr
            [[ -z "$server_addr" ]] && { colorize red "Server address cannot be empty."; press_key; return 1; }
            ;;
        2)
            read -p "[*] Enter Iran IPv6 address (e.g., [2a13:7b40:1::2:24d]): " server_addr
            [[ -z "$server_addr" ]] && { colorize red "Server address cannot be empty."; press_key; return 1; }
            if check_ipv6 "$server_addr"; then
                server_addr="${server_addr#[}"
                server_addr="${server_addr%]}"
            else
                colorize red "Invalid IPv6 address."
                press_key
                return 1
            fi
            ;;
        *)
            colorize red "Invalid option!"
            press_key
            return 1
            ;;
    esac

    # Tunnel port
    while true; do
        read -p "[*] Tunnel port (e.g., 443): " tunnel_port
        if [[ "$tunnel_port" =~ ^[0-9]+$ ]] && [ "$tunnel_port" -gt 22 ] && [ "$tunnel_port" -le 65535 ]; then
            break
        else
            colorize red "Enter a valid port (23-65535)"
        fi
    done

    # Transport type
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

    # TCP_NODELAY
    local nodelay=""
    read -p "[*] Enable TCP_NODELAY (true/false, press enter for true): " nodelay
    [[ -z "$nodelay" ]] && nodelay="true"
    while [[ "$nodelay" != "true" && "$nodelay" != "false" ]]; do
        read -p "[*] Enable TCP_NODELAY (true/false): " nodelay
        [[ -z "$nodelay" ]] && nodelay="true"
        [[ "$nodelay" != "true" && "$nodelay" != "false" ]] && colorize red "Enter true or false"
    done

    # Heartbeat
    local heartbeat="0"
    colorize yellow "Heartbeat disabled for high connection stability."

    # Token
    read -p "[-] Security Token (press enter for default 'RGT'): " token
    [[ -z "$token" ]] && token="RGT"

    # Service ports
    read -p "[*] Enter service ports (e.g., 8008,8080): " input_ports
    input_ports=$(echo "$input_ports" | tr -d ' ')
    IFS=',' read -r -a ports <<< "$input_ports"
    declare -a config_ports
    for port in "${ports[@]}"; do
        if [[ "$port" =~ ^[0-9]+$ ]] && [ "$port" -gt 22 ] && [ "$port" -le 65535 ]; then
            config_ports+=("$port")
            colorize green "Port $port added."
        else
            colorize red "Invalid port $port. Must be 23-65535."
        fi
    done
    [[ ${#config_ports[@]} -eq 0 ]] && { colorize red "No valid ports entered. Exiting."; sleep 2; return 1; }

    # Adjust IP format
    local_ip="127.0.0.1"

    # Generate client config
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

    # Create systemd service
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
    colorize green "Kharej server configuration completed for tunnel '$tunnel_name'."
}

# Function to edit tunnel
edit_tunnel() {
    local config_path="$1"
    local tunnel_type="$2"
    clear
    colorize cyan "Edit Tunnel $(basename "${config_path%.toml}")" bold
    echo
    if [[ "$tunnel_type" == "iran" ]]; then
        echo "1) Edit Tunnel Port"
        echo "2) Edit Tunnel Config Port"
        echo "3) Edit Tunnel Security Token"
        echo "4) Add new ports to Tunnel"
    else
        echo "1) Edit Tunnel Port"
        echo "2) Edit Tunnel Config Port"
        echo "3) Edit Tunnel Security Token"
        echo "4) Add new ports to Tunnel"
        echo "5) Edit Iran IP"
    fi
    read -p "Enter your choice (0 to return): " edit_choice
    case $edit_choice in
        1) edit_tunnel_port "$config_path" "$tunnel_type" ;;
        2) edit_config_port "$config_path" "$tunnel_type" ;;
        3) edit_security_token "$config_path" "$tunnel_type" ;;
        4) add_new_ports "$config_path" "$tunnel_type" ;;
        5) [[ "$tunnel_type" == "kharej" ]] && edit_iran_ip "$config_path" || { colorize red "Invalid option!"; sleep 1; } ;;
        0) return ;;
        *) colorize red "Invalid option!" && sleep 1 ;;
    esac
    # Restart service after any edit
    tunnel_name=$(basename "${config_path%.toml}" | sed 's/iran-//;s/kharej-//')
    service_name="RGT-${tunnel_type}-${tunnel_name}.service"
    systemctl restart "$service_name" || { colorize red "Failed to restart service after edit"; press_key; return 1; }
}

# Function to edit tunnel port
edit_tunnel_port() {
    local config_path="$1"
    local tunnel_type="$2"
    tunnel_name=$(basename "${config_path%.toml}" | sed 's/iran-//;s/kharej-//')
    while true; do
        read -p "[*] New tunnel port (e.g., 443): " new_port
        if [[ "$new_port" =~ ^[0-9]+$ ]] && [ "$new_port" -gt 22 ] && [ "$new_port" -le 65535 ]; then
            if [[ "$tunnel_type" == "iran" ]] && check_port "$new_port" "tcp"; then
                colorize red "Port $new_port is in use."
            else
                break
            fi
        else
            colorize red "Enter a valid port (23-65535)"
        fi
    done
    if [[ "$tunnel_type" == "iran" ]]; then
        sed -i "s/bind_addr = \".*:.*\"/bind_addr = \"${local_ip}:${new_port}\"/" "$config_path" || { colorize red "Failed to update tunnel port"; return 1; }
    else
        sed -i "s/remote_addr = \".*:.*\"/remote_addr = \"${server_addr}:${new_port}\"/" "$config_path" || { colorize red "Failed to update tunnel port"; return 1; }
    fi
    colorize green "Tunnel port updated to $new_port."
    press_key
}

# Function to edit config port
edit_config_port() {
    local config_path="$1"
    local tunnel_type="$2"
    tunnel_name=$(basename "${config_path%.toml}" | sed 's/iran-//;s/kharej-//')
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
        colorize red "Invalid port $new_port."
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
edit_security_token() {
    local config_path="$1"
    local tunnel_type="$2"
    tunnel_name=$(basename "${config_path%.toml}" | sed 's/iran-//;s/kharej-//')
    read -p "[*] Enter new security token (press enter for default 'RGT'): " new_token
    [[ -z "$new_token" ]] && new_token="RGT"
    sed -i "s/default_token = \".*\"/default_token = \"$new_token\"/" "$config_path"
    sed -i "s/token = \".*\"/token = \"$new_token\"/" "$config_path"
    colorize green "Security token updated to $new_token."
    press_key
}

# Function to add new ports
add_new_ports() {
    local config_path="$1"
    local tunnel_type="$2"
    clear
    colorize cyan "Adding new ports to $(basename "${config_path%.toml}")" bold
    echo
    local_ip="127.0.0.1"
    if [[ "$tunnel_type" == "iran" ]]; then
        local_ip="0.0.0.0"
        echo "Listen address:"
        echo "1) IPv4"
        echo "2) IPv6"
        read -p "Enter choice: " ip_choice
        case $ip_choice in
            1) colorize yellow "IPv4 Enabled" ;;
            2) colorize yellow "IPv6 Enabled"; local_ip="[::]" ;;
            *) colorize red "Invalid option! Defaulting to IPv4"; local_ip="0.0.0.0" ;;
        esac
    fi
    echo "Transport type:"
    echo "1) TCP"
    echo "2) UDP"
    read -p "Enter choice: " transport_choice
    case $transport_choice in
        1) service_transport="tcp" ;;
        2) service_transport="udp" ;;
        *) colorize red "Invalid option! Defaulting to TCP"; service_transport="tcp" ;;
    esac
    read -p "[*] Enter new ports (e.g., 8080,8081): " input_ports
    input_ports=$(echo "$input_ports" | tr -d ' ')
    IFS=',' read -r -a ports <<< "$input_ports"
    declare -a config_ports
    for port in "${ports[@]}"; do
        if [[ "$port" =~ ^[0-9]+$ ]] && [ "$port" -gt 22 ] && [ "$port" -le 65535 ]; then
            if [[ "$tunnel_type" == "iran" ]] && check_port "$port" "$service_transport"; then
                colorize red "Port $port is in use."
            else
                config_ports+=("$port")
                colorize green "Port $port added."
            fi
        else
            colorize red "Invalid port $port."
        fi
    done
    [[ ${#config_ports[@]} -eq 0 ]] && { colorize red "No valid ports entered."; sleep 2; return 1; }
    token=$(grep "default_token" "$config_path" | cut -d'=' -f2 | tr -d ' "')
    nodelay=$(grep "nodelay" "$config_path" | head -1 | cut -d'=' -f2 | tr -d ' ')
    for port in "${config_ports[@]}"; do
        if [[ "$tunnel_type" == "iran" ]]; then
            cat << EOF >> "$config_path"
[server.services.service${port}]
type = "$service_transport"
token = "$token"
bind_addr = "${local_ip}:${port}"
nodelay = $nodelay

EOF
        else
            cat << EOF >> "$config_path"
[client.services.service${port}]
type = "$service_transport"
token = "$token"
local_addr = "${local_ip}:${port}"
nodelay = $nodelay

EOF
        fi
    done
    colorize green "Ports added successfully."
    press_key
}

# Function to edit Iran IP (Kharej only)
edit_iran_ip() {
    local config_path="$1"
    tunnel_name=$(basename "${config_path%.toml}" | sed 's/kharej-//')
    echo "Iran server address:"
    echo "1) IPv4"
    echo "2) IPv6"
    read -p "Enter choice: " ip_choice
    case $ip_choice in
        1)
            read -p "[*] Enter new Iran IPv4 address (e.g., 85.9.102.245): " new_ip
            [[ -z "$new_ip" ]] && { colorize red "Server address cannot be empty."; press_key; return 1; }
            ;;
        2)
            read -p "[*] Enter new Iran IPv6 address (e.g., [2a13:7b40:1::2:24d]): " new_ip
            [[ -z "$new_ip" ]] && { colorize red "Server address cannot be empty."; press_key; return 1; }
            if check_ipv6 "$new_ip"; then
                new_ip="${new_ip#[}"
                new_ip="${new_ip%]}"
            else
                colorize red "Invalid IPv6 address."
                press_key
                return 1
            fi
            ;;
        *)
            colorize red "Invalid option!"
            press_key
            return 1
            ;;
    esac
    current_port=$(grep "remote_addr" "$config_path" | cut -d':' -f2 | cut -d'"' -f1)
    sed -i "s/remote_addr = \".*:.*\"/remote_addr = \"${new_ip}:${current_port}\"/" "$config_path" || { colorize red "Failed to update Iran IP"; return 1; }
    colorize green "Iran IP updated to $new_ip."
    press_key
}

# Function to manage tunnels
manage_tunnel() {
    clear
    if ! ls "$CONFIG_DIR"/*.toml &> /dev/null; then
        colorize red "No tunnels found." bold
        press_key
        return 1
    fi
    colorize cyan "List of existing tunnels:" bold
    echo
    local index=1
    declare -a configs
    declare -a config_types
    for config_path in "$CONFIG_DIR"/iran-*.toml; do
        if [[ -f "$config_path" ]]; then
            tunnel_name=$(basename "$config_path" .toml | sed 's/iran-//')
            kharej_config="$CONFIG_DIR/kharej-${tunnel_name}.toml"
            if [[ -f "$kharej_config" ]]; then
                tunnel_port=$(grep "remote_addr" "$kharej_config" 2>/dev/null | grep -oP ':(\d+)' | cut -d':' -f2)
                config_ports=$(grep -oP 'service[0-9]+' "$kharej_config" 2>/dev/null | sed 's/service//g' | sort -n | tr '\n' ',' | sed 's/,$//')
            else
                tunnel_port=$(grep "bind_addr" "$config_path" 2>/dev/null | grep -oP ':(\d+)' | cut -d':' -f2)
                config_ports=$(grep -oP 'service[0-9]+' "$config_path" 2>/dev/null | sed 's/service//g' | sort -n | tr '\n' ',' | sed 's/,$//')
            fi
            [[ -z "$tunnel_port" ]] && tunnel_port="Unknown"
            [[ -z "$config_ports" ]] && config_ports="Unknown"
            configs+=("$config_path")
            config_types+=("iran")
            echo -e "${MAGENTA}${index}${NC}) ${GREEN}Iran Tunnel ${tunnel_name}${NC} (Tunnel Port = ${YELLOW}${tunnel_port}${NC}) (Config Ports: ${YELLOW}${config_ports}${NC})"
            ((index++))
        fi
    done
    for config_path in "$CONFIG_DIR"/kharej-*.toml; do
        if [[ -f "$config_path" ]]; then
            tunnel_name=$(basename "$config_path" .toml | sed 's/kharej-//')
            tunnel_port=$(grep "remote_addr" "$config_path" 2>/dev/null | grep -oP ':(\d+)' | cut -d':' -f2)
            config_ports=$(grep -oP 'service[0-9]+' "$config_path" 2>/dev/null | sed 's/service//g' | sort -n | tr '\n' ',' | sed 's/,$//')
            [[ -z "$tunnel_port" ]] && tunnel_port="Unknown"
            [[ -z "$config_ports" ]] && config_ports="Unknown"
            configs+=("$config_path")
            config_types+=("kharej")
            echo -e "${MAGENTA}${index}${NC}) ${GREEN}Kharej Tunnel ${tunnel_name}${NC} (Tunnel Port = ${YELLOW}${tunnel_port}${NC}) (Config Ports: ${YELLOW}${config_ports}${NC})"
            ((index++))
        fi
    done
    echo
    read -p "Enter your choice (0 to return): " choice
    [[ "$choice" == "0" ]] && return
    while ! [[ "$choice" =~ ^[0-9]+$ ]] || (( choice < 1 || choice > ${#configs[@]} )); do
        colorize red "Invalid choice. Enter a number between 1 and ${#configs[@]} or 0 to return."
        read -p "Enter your choice: " choice
        [[ "$choice" == "0" ]] && return
    done
    selected_config="${configs[$((choice - 1))]}"
    tunnel_type="${config_types[$((choice - 1))]}"
    tunnel_name=$(basename "${selected_config%.toml}" | sed 's/iran-//;s/kharej-//')
    service_name="RGT-${tunnel_type}-${tunnel_name}.service"
    check_consecutive_errors "$service_name"
    clear
    colorize cyan "Commands for Tunnel $tunnel_name:" bold
    echo
    colorize green "1) Edit Tunnel" bold
    colorize yellow "2) Restart Tunnel" bold
    colorize red "3) Remove Tunnel" bold
    colorize cyan "4) View Logs" bold
    colorize cyan "5) View Status" bold
    read -p "Enter your choice (0 to return): " sub_choice
    case $sub_choice in
        1) edit_tunnel "$selected_config" "$tunnel_type" ;;
        2) restart_service "$service_name" ;;
        3) destroy_tunnel "$selected_config" "$tunnel_type" ;;
        4) view_tunnel_logs "$service_name" ;;
        5) view_tunnel_status "$service_name" ;;
        0) return ;;
        *) colorize red "Invalid option!" && sleep 1 ;;
    esac
}

# Function to destroy tunnel
destroy_tunnel() {
    local config_path="$1"
    local tunnel_type="$2"
    tunnel_name=$(basename "${config_path%.toml}" | sed 's/iran-//;s/kharej-//')
    service_name="RGT-${tunnel_type}-${tunnel_name}.service"
    service_path="${SERVICE_DIR}/${service_name}"
    [[ -f "$config_path" ]] && rm -f "$config_path"
    [[ -f "$service_path" ]] && systemctl disable --now "$service_name" && rm -f "$service_path"
    systemctl daemon-reload
    colorize green "Tunnel $tunnel_name destroyed successfully."
    press_key
}

# Function to restart service
restart_service() {
    local service_name="$1"
    colorize yellow "Restarting $service_name..." bold
    if systemctl list-units --type=service | grep -q "$service_name"; then
        systemctl restart "$service_name"
        colorize green "Tunnel restarted successfully."
    else
        colorize red "Tunnel $service_name not found."
    fi
    press_key
}

# Function to view tunnel logs
view_tunnel_logs() {
    clear
    journalctl -eu "$1"
    press_key
}

# Function to view tunnel status
view_tunnel_status() {
    clear
    systemctl status "$1"
    press_key
}

# Function to display RGT Tools menu (placeholder for future tools)
rgt_tools() {
    clear
    colorize cyan "RGT Tools" bold
    echo
    colorize yellow "This section is under development. No tools available yet."
    press_key
}

# Function to remove rgt core
remove_core() {
    clear
    if ls "$CONFIG_DIR"/*.toml &> /dev/null; then
        colorize red "Delete all tunnels before removing RGT core."
        press_key
        return 1
    fi
    read -p "Confirm removal of RGT core? (y/n): " confirm
    if [[ "$confirm" =~ ^[yY]$ ]]; then
        rm -rf "$CONFIG_DIR"
        colorize green "RGT core removed."
    else
        colorize yellow "Removal canceled."
    fi
    press_key
}

# Function to display logo
display_logo() {
    echo -e "${CYAN}"
    cat << "EOF"
██████╗  ██████╗ ████████╗
██╔══██╗██╔═══╗╚╗   ██╔══╝
██████╔╝██║█████║   ██║   RGT Tunnel
██╔╗██║ ██║   ██║   ██║   (by @Coderman_ir)
██║║██║ ╚██████╔╝   ██║
╚═╝╚══╝  ╚═════╝    ╚═╝
-----------------------------------
EOF
}

# Function to display server info
display_server_info() {
    SERVER_IP=$(hostname -I | awk '{print $1}')
    echo -e "${CYAN}IP Address:${NC} $SERVER_IP"
    if [[ -f "${RGT_BIN}" ]]; then
        echo -e "${CYAN}core Installed:${NC} ${GREEN}Yes${NC}"
    else
        echo -e "${CYAN}core Installed:${NC} ${RED}No${NC}"
    fi
    echo -e "${YELLOW}-----------------------------------${NC}"
}

# Function to display menu
display_menu() {
    clear
    display_logo
    echo -e "${CYAN}Version: ${YELLOW}1.0${NC}"
    echo -e "${CYAN}Github: ${YELLOW}github.com/black-sec/RGT${NC}"
    display_server_info
    echo
    colorize green "1) Setup New Tunnel" bold
    colorize green "2) Manage Tunnel" bold
    colorize green "3) Install RGT core" bold
    colorize red "4) Uninstall RGT core" bold
    colorize yellow "5) Update Script" bold
    colorize cyan "6) RGT Tools" bold
    colorize yellow "7) Exit" bold
    echo
}

# Main loop
install_dependencies
mkdir -p "$CONFIG_DIR"
# Make script executable as 'RGT' command on first run
if [[ ! -f "${SCRIPT_PATH}" ]]; then
    cp "$0" "${SCRIPT_PATH}"
    chmod +x "${SCRIPT_PATH}"
    colorize green "Script is now executable as 'RGT' command." bold
fi
while true; do
    display_menu
    read -p "Choose an option: " choice
    case $choice in
        1)
            clear
            colorize cyan "Select Tunnel Type:" bold
            echo "1) Direct"
            echo "2) Reverse"
            read -p "Enter choice: " tunnel_type
            case $tunnel_type in
                1)
                    colorize yellow "Direct tunnel configuration is under development."
                    press_key
                    ;;
                2)
                    clear
                    colorize cyan "Select Server Location:" bold
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
