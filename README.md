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


# Part 1: The control router

The "control experiment". Let's implement router functionality using just the `iptables` and `nnmcli` packages. The whole router process will thus happen in the kernel space (I THINK?).

### 1. Check that the Wi-Fi interfaces aren't disabled
```
nmcli radio wifi
```
If it returns something like:
```
wifi: disabled
```
You can enable Wi-Fi by running:
```
nmcli radio wifi on
```

### 1. Enable hotspot on Pi
Use the built-in WiFi module to broadcast a hotspot network on `wlan0`. Replace `<hotspot-name>` and `<hotspot-password>` accordingly:
```bash
sudo nmcli device wifi hotspot ssid <hotspot-name> password <hotspot-password> ifname wlan0
```

Then, to enable packet forwarding, edit `/etc/sysctl.conf` and uncomment this line:
```
net.ipv4.ip_forward=1
```

Apply the changes with:
```bash
sudo sysctl -p
```

You can see the connection with `sudo nmcli connection show`, activate it with  `sudo nmcli connection up`, and deactivate it with `sudo nmcli connection down`.

### 2. Forward traffic from Pi to Internet

Forward traffic from the `wlan0` interface to the `eth0` interface:
```bash
sudo iptables -A FORWARD -i wlan0 -o eth0 -j ACCEPT
```

Forward traffic from the `eth0` interface to the `wlan0` interface **for already established or related connections** 
```bash
sudo iptables -A FORWARD -i eth0 -o wlan0 -m state --state ESTABLISHED,RELATED -j ACCEPT
```

Set up network address translation (NAT) so that traffic leaving the `eth0` interface will always appear to come from the IP address of the `eth0` interface:
```bash
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
```

You can verify the rules with:
```sh
sudo iptables -L FORWARD -v -n
sudo iptables -t nat -L -v -n
```

### 3. Save iptables rules

Install `iptables-persistent` package:
```sh
sudo apt install iptables-persistent
```
During installation, it will prompt you to save the current rules. You can choose yes, but we will change these rules part 2.
# Part 2: Intercepting packets in the user-space

I'm not trying to rewrite the Linux network stack here, so we'll allow the kernel's netfilter framework to handle the initial packet processing.
However, we can intercept packets being processed using the [libnetfilter_queue](https://netfilter.org/projects/libnetfilter_queue/doxygen/html/) library and handle them with our custom logic in the user-space.

### 1. Install libnetfilter-queue

```sh
sudo apt install libnetfilter-queue-dev
```

### 2. Direct packets to NFQUEUE

Let's first remove the forwarding rules we set up in part 1:
```sh
sudo iptables -D FORWARD -i wlan0 -o eth0 -j ACCEPT
sudo iptables -D FORWARD -i eth0 -o wlan0 -m state --state ESTABLISHED,RELATED -j ACCEPT
```

We can keep the MASQUERADE rule for now, though we can manually implement that logic later.

Let's set up another forwarding rule from `wlan0` to `eth0` but this time we're directing packets to the NFQUEUE target for processing.
```sh
sudo iptables -A FORWARD -i wlan0 -o eth0 -j NFQUEUE --queue-num 0
sudo iptables -A FORWARD -i eth0 -o wlan0 -m state --state ESTABLISHED,RELATED -j NFQUEUE --queue-num 0
```

and of course save whenever you want the changes to be persistent:
```sh
sudo iptables-save | sudo tee /etc/iptables/rules.v4
```

### 3. Intercept packets in python

Now the packets are in NFQUEUE, we can write a python script to handle them.

There's a [`router_monitor.py`](router_monitor.py) in this repo that does this. To run it, go the the RouteWars directory and:

Install pip:
```
sudo apt install python3-pip
```

Create virtual environment:
```
python3 -m venv env
```

Activate env and install dependent libraries:
```
source env/bin/activate
pip3 install scapy netfilterqueue
```

Deactivate env and run code with sudo privileges:
```
deactivate
sudo router_monitor.py
```
