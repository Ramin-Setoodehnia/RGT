![Menu](https://github.com/black-sec/RGT/blob/main/Menu.png)

[Persian Readme](https://github.com/black-sec/RGT/blob/main/README_FA.md)
- ** Telegram channel : https://t.me/rogozar_dev
- ** Telegram Group : https://t.me/rogozar_team

## RGT Tunnel

### RGT Tunnel Manager

The RGT script is a powerful tool for setting up tunnels based on TCP and UDP protocols, supporting both direct and reverse methods. The resource usage of this tunnel is optimized, allowing you to set up your tunnel in just a few seconds.

## ⚙️ Features

- **Fast Setup**: Set up reverse or direct (Iran ↔ Outside) tunnels in a few simple steps.
- **Bandwidth Monitoring**: Check tunnel bandwidth usage with the lightweight `vnstat` tool.
- **Automatic Error Management**: Detect consecutive errors in logs and automatically restart the tunnel.
- **High Flexibility**: Supports TCP/UDP protocols, IPv4/IPv6 addresses, and custom ports.
- **Accessible Command**: After the first run, the script is available via the `RGT` command.
- **Systemd Integration**: Tunnels run as stable services.
- **Attractive User Interface**: Colorful menus and clear messages for a better user experience.

##### Download and Run the Script:

**Quick Execution:**
```
bash <(curl -Ls https://raw.githubusercontent.com/black-sec/RGT/main/rgt_manager.sh)
```

Download the script from the link below:
```
wget https://github.com/black-sec/RGT/raw/main/rgt_manager.sh -O /root/rgt_manager.sh
chmod +x /root/rgt_manager.sh
```

Alternatively, upload the `rgt_manager.sh` file via SFTP to the `/root/` directory.

Run the script:
```
RGT
```
#### Quick Start Guide

##### Run RGT:

If your server has access to GitHub:
```
wget https://github.com/black-sec/RGT/raw/main/core/RGT_x86_64_linux.zip -O /root/RGT/RGT_x86_64_linux.zip
```

If you don’t have access to GitHub, upload the `RGT_x86_64_linux.zip` file via SFTP to the `/root/RGT/` directory on your server:
```
put RGT_x86_64_linux.zip /root/RGT/RGT_x86_64_linux.zip
```

#### ✅ Guide to Setting Up a Direct Tunnel with RGT Script

First, install the RGT core with option 3 on both servers (if it fails to install in Iran, download it manually, upload it via SFTP, extract it, etc.).

🟢 **Configure the Outside Server first:**

1. Select option 1 (Direct).
2. Choose "Server Kharej" (Outside Server).
3. Enter a name for the tunnel (e.g., Test2).
4. Select the IP type.
5. Enter the Iran server IP.
6. Enter the tunnel port (not the configuration port).
7. Enter a VXLAN ID value, e.g., 100 (use the same value on the Iran server).
8. Enter a bridge IP for the outside server, e.g., 10.0.10.2 (this IP will be needed on the Iran server).
9. Proceed to the Iran server.

🔴 **Configure the Iran Server:**

1. Select option 1 (Direct).
2. Choose "Iran Server".
3. Enter a name for the tunnel (e.g., Test2).
4. Select the IP type.
5. Enter the outside server IP.
6. Enter the tunnel port (not the configuration port).
7. Enter a bridge IP for the Iran server, e.g., 10.0.10.1.
8. Enter the outside server bridge IP, e.g., 10.0.10.2.
9. Enter the VXLAN ID you set on the outside server.
10. Enter your configuration port, e.g., 8080.

#### Important Notes

- **GitHub Access**: If your server cannot access GitHub, place the `RGT_x86_64_linux.zip` file in `/root/RGT/` and run the script with the `RGT_LOCAL_ZIP` variable.
- **Bandwidth Monitoring**: After setting up the tunnel, use the bandwidth monitoring option to check usage (coming soon).
- **Error Resolution**: The script automatically detects two consecutive errors in logs and restarts the tunnel.

#### Support

- **GitHub Repository**: [black-sec/RGT](https://github.com/black-sec/RGT)
- **Access Issues**: If you lack GitHub access, coordinate with your server administrator to upload the files.

   ## ❤️Donation
  
 <summary>wallet Address</summary>

If the project was useful to you, you can use the following addresses for financial support:

| coin |  wallet Address |
|-------|------------|
| **Tron** | `TFoHrr4C9aXzt5YSA2nLcNRBgnRiBR57VL` |
| **DOGE** | `DDTdqfYR29vuqfHgfoG26VySUFE4BxUT5w` |
| **TON** | `UQATjmqCOOkHGYUlyjzWB6KIDjPogpa_oIEraPeXNRfGZAWh` |
| **LTC** | `ltc1q377z5q9ggjkng4s37fdtj85nw97svmhsg420a6` |


## Stargazers over time
[![Stargazers over time](https://starchart.cc/black-sec/RGT.svg?variant=adaptive)](https://starchart.cc/black-sec/RGT)
