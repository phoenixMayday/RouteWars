# RouteWars

For future reference, this file will detail how I went about the project.

# Setting up development environment

## Set up VPS with Oracle and Cloudflare
I'm paying £1.60 a month for an Oracle Cloud instance which I can SSH into it through its public iPv4.
If you have a domain name you can use Cloudflare to SSH through there:
1. Add a DNS record for your domain whose content is the iPv4 of the VPS.
2. Set the proxy status must unticked— "DNS Only".

## Port forward
I'm going to make it so port 2222 on the VPS forwards to port 22 on the Pi. Follow these steps on each machine:
### On the VPS:
1. Edit /etc/ssh/sshd_config
2. Uncomment `# GatewayPorts no` and change it to `GatewayPorts yes`
3. Open port in the firewall
```sh
sudo firewall-cmd --permanent --add-port=2222/tcp
sudo firewall-cmd --reload
```
### On the Pi:
1. Make sure VPS authorises the Pi's ssh key, e.g. `ssh-copy-id user@mydomain.com`
2. Install autossh
```sh
sudo apt update
sudo apt install autossh -y
```
3. Create file `/etc/systemd/system/reverse-ssh.service`:
```ini
[Unit]
Description=Reverse SSH Tunnel
After=network.target

[Service]
User=piuser
ExecStart=/usr/bin/autossh -M 0 -o "ServerAliveInterval 30" -o "ServerAliveCountMax 3" -o "ExitOnForwardFailure=yes" -N -R 2222:localhost:22 vpsuser@mydomain.com
Restart=always
RestartSec=10
KillMode=process

[Install]
WantedBy=multi-user.target
```
- Breakdown of the autossh command:
	- `-M 0` disables autossh's monitoring ports (optional but prevents unnecessary ports from being used).
	- `-o "ServerAliveInterval 30"`: Sends a keep-alive packet every **30 seconds**.
	- `-o "ServerAliveCountMax 3`: If **3 consecutive keep-alive packets** fail, the connection is terminated. This ensures the tunnel reconnects if there's a temporary network issue.
	- `-o "ExitOnForwardFailure=yes"`: Ensures `autossh` exits if the port forwarding fails, allowing the service to restart and retry.
	- `-f` runs it in the background.
	- `-N` prevents command execution (just forwarding).
	- `-R 2222:localhost:22` sets up the reverse tunnel.
4. Enable and start service:
```sh
sudo systemctl daemon-reload
sudo systemctl enable reverse-ssh
sudo systemctl start reverse-ssh
```
### On your machine:
On the machine you want to access the Pi from (e.g. laptop), add this to your ~/.ssh/config:
```
Host mypi
    HostName mydomain.com
    Port 2222
    User piuser
```

