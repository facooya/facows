# Facows
Site of use `Facows`: `dev.facooya.com`.
- Originaly `facooya.com` (`www.facooya.com`), but have not content. So please go to the `dev.facooya.com`.

**Limitations**
- Linux only.
- Only SSL, must have ssl certificate and private key.
- Not support PHP, only static files.
- Only http 1.1.
- Poll method.
- Only html extendsion for clean url, but forced.
- Not support upload/download for large files, because socket timeout 2 seconds.

**Features**
- Support configuration file.
- Support regist to system daemon.
- If NFT true in conf file, ip ban of dos or flood attack.
- URL redirect from http to https.
- Redirect html extenstion for clean url.

**Implement**
- poll.
- - Must upgrade will epoll, may upgrade will io_uring.
- kTLS.
- - If fail kernel TLS, convert to user-space TLS.

### Default Path
- Web root: `/var/www/facows/`
- Log: `/var/log/facows/`
- Configure: `/etc/facows/`

### Dependency Install
```sh
sudo apt update
sudo apt install git make libssl-dev nftables libnftables-dev
```
- `git` - For the `git clone`
- `make` - Build for facows
- `libssl-dev` - Open ssl library in C
- `nftables` - Network filter for IP ban
- `libnftables-dev` - Network filter library in C

Register nftables to systemd:
```sh
sudo systemctl enable nftables
sudo systemctl start nftables
```

**Check for kTLS**
Openssl version over than 3.0.4.
Linux kernel version over than 5.6.

kTLS:
```sh
# Check
lsmod | grep tls

# Enable
sudo modprobe tls
```

### Quick Start
**Build**
```sh
git clone https://github.com/facooya/facows.git
cd facows
make
sudo make install
```

**Configuration**
> [!WARNING]
> If `NFT` configuration true, deny all port except Facows port defined by `/etc/facows/facows.conf`.
> Enable `ALLOW_PORTS` and write allow port in `/etc/facows/facows.conf`.

Modifiy `/etc/facows/facows.conf` domain and SSL path.  
- Log not support yet.

**Execute**
Manual:
```sh
sudo ./build/facows
```

System daemon:
```sh
sudo systemctl enable facows
sudo systemctl start facows
```

**Exit**
Manual:
Program exit `ctrl + c` or `kill PID`.  
> [!WARNING]
> Must not `kill -9 PID`. If already used and `NFT true` in `/etc/facows/facows.conf`, try `sudo nft table delete netdev facows; sudo nft table delete inet facows` for network.

System daemon:
```sh
sudo systemctl stop facows
```

**Uninstall**
```sh
sudo make uninstall
```

Manual path:
```sh
/usr/local/bin/facows # For 'ExecStart' path in 'systemd'.
/etc/systemd/system/facows.service # For 'systemd'.

/etc/facows/ # For configuration to 'Facows'.
/usr/share/facows/ # For error pages.
/var/www/facows/ # For example pages.
```

**Upgrade**
System deamon:
```sh
sudo systemctl stop facows
make
sudo make install
sudo systemctl restart facows
```

### Configuration File
If chagned:
```sh
sudo systemctl restart facows
```

---

### Reference Links
- Create SSL Certificate [SSL](/doc/ssl.md)

---

> FWS: Facooya Web Server  
> FACOWS: FACOoya Web Server  
> Maintained by Facooya and Fanone Facooya, 2026  
