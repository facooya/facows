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
Modifiy `facows.conf.dist` domain and path.  
- Log not support yet.
Locate manually configure file:
```bash
sudo mkdir -p /etc/facows/
sudo cp facows.conf.dist /etc/facows/facows.conf
```

---

> FACOWS: FACOoya Web Server  
> Authors 2026 Facooya and Fanone Facooya
