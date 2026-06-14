# SSL
## Certbot (Let's Encrypt)
This guide use `--webroot` certificate method.

> [!IMPORTANT]
> - Remove `--dry-run` option, if apply.

**Install**
```sh
sudo apt install certbot
```

**Options**
- `--dry-run`: For test. if apply, remove `--dry-run` option.
- `--webroot`: Certificate option.
- `-w`: (usage: `-w <webroot_path>`).
- `-d`: (usage: `-d <domain>`) important fist domain, it will be certification name.

**Create**
> [!IMPORTANT]
> - First domain will be certification name and directory name.
> - Write all subdomains manually to apply SSL.

For example:
```sh
sudo certbot certonly --dry-run --webroot \
-w <webroot> -d <domain>
```
```sh
sudo certbot certonly --dry-run --webroot \
-w /var/www/example/ -d example.com \
-w /var/www/example/www/ -d www.example.com \
-w /var/www/example/test/ -d test.example.com
```

Default path:
- Certification file: `/etc/letsencrypt/live/example.com/fullchain.pem`
- Private key file: `/etc/letsencrypt/live/example.com/privkey.pem`

Check certificate file: 
```sh
sudo certbot certificates
```

**Renew**
For example:
```sh
sudo certbot renew --dry-run
# OR
sudo certbot renew --dry-run --cert-name example.com
```

Check automatic renew timer in `systemd`:
```sh
systemctl list-timers | grep certbot
```

**Expand**
> [!IMPORTANT]
> - Writing already exist subdomains by certificate file.

For example:
```sh
sudo certbot certonly --dry-run --webroot \
--cert-name <first_domain> --expand \
-w <webroot> -d <domain> \
-w <new_webroot> -d <new_domain> \
```
```sh
sudo certbot certonly --dry-run --webroot \
--cert-name example.com --expand \
-w /var/www/example/ -d example.com \ # already exist
-w /var/www/example/www/ -d www.example.com \ # already exist
-w /var/www/example/test/ -d test.example.com \ # already exist
-w /var/www/example/add/ -d add.example.com \ # add new
-w /var/www/example/expand/ -d expand.example.com \ # add new

```

---

## Apply in Facows
Example, before certificate via `certbot` (Let's Encrypt).
Open `etc/facows.conf`, or already excute `make install` open `/etc/facows/facows.conf`.

Apply: `SSL_CERT "/etc/letsencrypt/live/<first_domain>/fullchain.pem"`.  
For example in `facows.conf`:
```
SSL_CERT "/etc/letsencrypt/live/example.com/fullchain.pem"
SSL_KEY "/etc/letsencrypt/live/example.com/privkey.pem"
```

---

## SSL in C
```sh
sudo apt install libssl-dev
```
```c
#include <openssl/ssl.h>
```

---

> Authors 2026 Facooya and Fanone Facooya
