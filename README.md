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
sudo make install
```

**Configuration**
> [!WARNING]
> If `NFT` configuration true, deny all port except Facows port defined by `/etc/facows/facows.conf`.
> Enable `ALLOW_PORTS` and write allow port in `/etc/facows/facows.conf`.

Modifiy `/etc/facows/facows.conf` domain and SSL path.  
- Log not support yet.

**Execute**
```bash
sudo ./build/facows
```

**Exit**
Program exit `ctrl + c` or `kill PID`.  
> [!WARNING]
> Must not `kill -9 PID`. If already used and `NFT true` in `/etc/facows/facows.conf`, try `sudo nft table delete netdev facows; sudo nft table delete inet facows` for network.

---

> FWS: Facooya Web Server  
> FACOWS: FACOoya Web Server   
> Authors 2026 Facooya and Fanone Facooya
