# Facows
Testing ...

**Limitations**
- Only SSL, must have ssl certificate and private key.
- Not support PHP, only static files.
- Only http 1.1
- Support on linux
- Poll method
- Only html extendsion for clean url, but forced.
- Not support upload/download for large files, because socket timeout 2 seconds.

**Features**
- Support configuration file
- Support regist to system daemon
- If NFT true in conf file, ip ban of dos or flood attack.
- URL redirect from http to https
- Redirect html extenstion for clean url

### Default Path
- Web root: `/var/www/facows/`
- Log: `/var/log/facows/`
- Configure: `/etc/facows/`

### Dependancy Install
```bash
sudo apt update
sudo apt install git make libssl-dev nftables libnftables-dev libkmod-dev libnl-3-dev libnl-route-3-dev
```
- `git` - For the `git clone`
- `make` - Build for facows
- `libssl-dev` - Open ssl library in C
- `nftables` - Network filter for IP ban
- `libnftables-dev` - Network filter library in C

Register nftables to systemd:
```bash
sudo systemctl enable nftables
sudo systemctl start nftables
```

### Quick Start
**Build**
```bash
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
```bash
sudo ./build/facows
```

System daemon:
```bash
sudo useradd -r -s /usr/sbin/nologin facows
sudo systemctl enable facows
sudo systemctl start facows
```

**Exit**
Manual:
Program exit `ctrl + c` or `kill PID`.  
> [!WARNING]
> Must not `kill -9 PID`. If already used and `NFT true` in `/etc/facows/facows.conf`, try `sudo nft table delete netdev facows; sudo nft table delete inet facows` for network.

System daemon:
```bash
sudo systemctl stop facows
```

**Update**
System deamon:
```bash
sudo systemctl stop facows
make
sudo make install
sudo systemctl restart facows
```

---

> FWS: Facooya Web Server  
> FACOWS: FACOoya Web Server   
> Authors 2026 Facooya and Fanone Facooya
