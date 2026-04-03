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
sudo systemctl enable nftables
sudo systemctl start nftables
```
- `git` - For the `git clone`
- `make` - Build for facows
- `libssl-dev` - Open ssl library for C
- `nftables` - Network filter for IP black

### Quick Start
```bash
git clone https://github.com/facooya/facows.git
cd facows
make
sudo ./build/facows
```

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
```

---

> FACOWS: FACOoya Web Server  
> Authors 2026 Facooya and Fanone Facooya
