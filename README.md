# WatchLeaks

WatchLeaks est un tableau de bord Symfony qui supervise des domaines, importe des fuites et attaques depuis des sources OSINT publiques, et fournit un audit manuel (Telegram/paste, HIBP, DeHashed, Intelligence X). L'interface responsive propose un mode clair/sombre persistant.

## 1. Prérequis

- Linux (Ubuntu/Debian recommandé)
- PHP 8.1+ avec extensions : `pdo_mysql`, `intl`, `mbstring`, `xml`, `curl`, `zip`
- Composer
- MySQL/MariaDB
- Apache + PHP-FPM ou `libapache2-mod-php`
- phpMyAdmin (optionnel)

```bash
sudo apt update
sudo apt install -y php php-mysql php-intl php-mbstring php-xml php-curl php-zip composer mysql-server apache2 libapache2-mod-php phpmyadmin
```

## 2. Cloner le projet

Le dépôt est privé : authentifie-toi avec `gh auth login` ou utilise un token.

```bash
sudo git clone https://github.com/Jihedrz/watchleaks.git /opt/watchleaks
cd /opt/watchleaks
composer install --no-interaction
```

 Si tu clones ailleurs, remplace `/opt/watchleaks` dans toutes les commandes ci-dessous et dans le fichier `watchleaks.service`.

## 3. Configuration environnement

Les fichiers versionnés `.env` et `.env.test` contiennent des valeurs factices. Les vraies valeurs vont dans `.env.local` et `.env.test.local`, ignorés par git.

```bash
cp .env .env.local
cp .env.test .env.test.local
```

Génère un secret puis édite `.env.local` :

```bash
php -r 'echo bin2hex(random_bytes(16)), PHP_EOL;'
nano .env.local
```

Exemple de `.env.local` :

```dotenv
APP_SECRET=colle_le_secret_genere_ici
DATABASE_URL="mysql://xmap:CHANGE_ME_DB_PASSWORD@127.0.0.1:3306/xmap_db?serverVersion=8.0.46&charset=utf8mb4"
```

Édite aussi `.env.test.local` avec la même URL (Symfony ajoutera automatiquement le suffixe `_test`, donc `xmap_db` devient `xmap_db_test`).

## 4. Base de données

```bash
sudo mysql -e "CREATE DATABASE IF NOT EXISTS xmap_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci; CREATE DATABASE IF NOT EXISTS xmap_db_test CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci; CREATE USER IF NOT EXISTS 'xmap'@'localhost' IDENTIFIED BY 'CHANGE_ME_DB_PASSWORD'; GRANT ALL PRIVILEGES ON xmap_db.* TO 'xmap'@'localhost'; GRANT ALL PRIVILEGES ON xmap_db_test.* TO 'xmap'@'localhost'; FLUSH PRIVILEGES;"
```

## 5. Migrations et comptes

```bash
cd /opt/watchleaks
php bin/console doctrine:migrations:migrate --no-interaction
php bin/console app:seed --with-client
```

Comptes créés :

- Admin : `admin@watchleaks.local` / `admin123`
- Client : `client@watchleaks.local` / `client123`

Change ces mots de passe immédiatement après installation.

## 6. Domaines de benchmark

Pour tester le collecteur avec des domaines célèbres et massivement présents dans les bases de fuites :

```bash
php bin/console app:seed-benchmark-domains --force
```

Jeu installé : `canva.com`, `adobe.com`, `dropbox.com`, `23andme.com`, `ticketmaster.com`, `santander.com`.

Cette commande supprime les domaines existants ainsi que leurs attaques/fuites associées, puis crée les 6 domaines ci-dessus avec monitoring activé.

Évite `linkedin.com`, `yahoo.com` et les méga-listes pour un premier test : les volumes sont énormes et la première synchronisation peut être très longue.

## 7. Lancer manuellement

```bash
cd /opt/watchleaks
chmod +x watchleaks.sh
./watchleaks.sh start
./watchleaks.sh status
```

Commandes utiles :

```bash
./watchleaks.sh sync    # synchronisation unique des feeds
./watchleaks.sh scan    # scan de fuite unique
./watchleaks.sh stop
./watchleaks.sh restart
```

Logs :

- `/tmp/watchleaks-web.log`
- `/tmp/watchleaks-sync.log`
- `/tmp/watchleaks-leaks.log`

## 8. Lancer automatiquement au boot (systemd)

```bash
sudo cp /opt/watchleaks/watchleaks.service /etc/systemd/system/watchleaks.service
sudo systemctl daemon-reload
sudo systemctl enable --now watchleaks.service
systemctl status watchleaks --no-pager
```

Le service démarre Apache, MySQL, le serveur web PHP et les 2 workers.

## 9. Accès

- WatchLeaks : `http://localhost:8000`
- WatchLeaks depuis le réseau local : `http://<IP_DE_LA_MACHINE>:8000`
- phpMyAdmin : `http://localhost/phpmyadmin`
- Base : `xmap_db`
- Utilisateur MySQL : `xmap` / `CHANGE_ME_DB_PASSWORD`

## 10. Tests

```bash
cd /opt/watchleaks
COMPOSER_ALLOW_SUPERUSER=1 composer test
```

Si l'utilisateur MySQL root a un mot de passe :

```bash
TEST_DB_ADMIN_URL='mysql://root:MOT_DE_PASSE@localhost:3306/xmap_db?serverVersion=8.0.46&charset=utf8mb4' COMPOSER_ALLOW_SUPERUSER=1 composer test
```

## 11. Sources et options

Sources déjà intégrées automatiquement :

- XposedOrNot
- ransomware.live
- Hudson Rock
- LeakRadar

Dans `Settings` :

- active **Enable automatic leak scanning** ;
- clique sur **Sync Now** ;
- ajoute optionnellement les clés XposedOrNot et LeakRadar ;
- configure l’**Attacks API** avec ton endpoint JSON (URL, GET/POST, header d’auth, token).

La page **Domain Audit** génère des recherches Telegram/paste et une checklist de remédiation sans scraper ni stocker de dumps.

## 12. Sécurité avant mise en production

- change `admin123` et `client123` ;
- régénère `APP_SECRET` ;
- mets HTTPS derrière un reverse proxy ;
- limite l’accès à phpMyAdmin ;
- ne commite jamais `.env.local` ou `.env.test.local`.
