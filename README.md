# Facows
Testing ...

### Default Path
- Web root: `/var/www/facows/`
- Log: `/var/log/facows/`
- Configure: `/etc/facows/`

### Dependancy Install
```bash
sudo apt update
sudo apt install git make libssl-dev nftables
```
- `git` - For the `git clone`
- `make` - Build for facows
- `libssl-dev` - Open ssl library for C
- `nftables` - Network filter for IP black

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
> Deny all port except Facows port defined by `facows.conf.dist`.
> Add more port number in `facows_nft.conf.dist` at `facows_chain` below `tcp dport %d accept;`, or comment all line at `facows_chain` section, this way can not IP black to any attack.

> [!CAUTION]
> Overwirte forced `ifb` module and queue discipline on `tc` by `facows_tc.conf.dist`.

Make install not support yet.  
Modifiy `facows.conf.dist` domain and SSL path.  
- Log not support yet.
Locate manually files:
```bash
sudo mkdir -p /etc/facows/
sudo cp facows.conf.dist /etc/facows/facows.conf
sudo mkdir -p /usr/share/facows/
sudo cp error_page.html /usr/share/facows/

sudo cp facows_nft.conf.dist /etc/facows/facows_nft.conf
sudo cp facows_tc.conf.dist /etc/facows/facows_tc.conf
```

**Execute**
```bash
sudo ./build/facows
```

---

> FACOWS: FACOoya Web Server  
> Authors 2026 Facooya and Fanone Facooya
