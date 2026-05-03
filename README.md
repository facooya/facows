# Facows
Testing ...

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
```

**Configuration**
> [!WARNING]
> If `NFT` configuration true, deny all port except Facows port defined by `facows.conf`.
> Enable `ALLOW_PORTS` and write allow port in `facows.conf`.

Make install not support yet.  
Modifiy `facows.conf` domain and SSL path.  
- Log not support yet.
Locate manually files:
```bash
sudo mkdir -p /var/www/facows/
sudo mkdir -p /etc/facows/
sudo cp etc/facows.conf /etc/facows/
sudo mkdir -p /usr/share/facows/
sudo cp share/error_page.html /usr/share/facows/
```

**Execute**
```bash
sudo ./build/facows
```

---

> FWS: Facooya Web Server  
> FACOWS: FACOoya Web Server   
> Authors 2026 Facooya and Fanone Facooya
