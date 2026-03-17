# Facows
Testing ...

### Default Path
- Web root: `/var/www/facows/`
- Log: `/var/log/facows/`
- Configure: `/etc/facows/`

### Dependancy Install
```bash
sudo apt install git make libssl-dev
```
- `git` - For the `git clone`
- `make` - Build for facows
- `libssl-dev` - Open ssl library for C

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
```

---

> FACOWS: FACOoya Web Server  
> Authors 2026 Facooya and Fanone Facooya
