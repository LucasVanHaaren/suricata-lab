# Packet loss impact on Suricata detection

Le lab que j'ai construit s'articule autour de plusieurs conteneurs exposant différents services à savoir :
- FTP
- HTTP
- SMB
- TCP (bind shell)

Un conteneur client interagit avec chaque service et pour chaqun d'entre eux, télécharge les fichiers contenus dans le dossier assets (monté dans chaque conteneur en RO).

Un dernier conteneur s'occupe de capturer le réseau interne a docker (le bridge crée par la stack docker compose pour etre exact) et dump le pcap dans le dossier samples.


- Pour mettre a jour la liste des fichiers (si ajout plus tard) :
```
find ./assets/ -type f | sed 's/\.\/assets\///g' > client/assets.lst
```

## Setup

- For simplicity, I have set up a compose file which pop up some containers and serves files in `assets` dir over diffrents protocols (HTTP, FTP, SMB, ...)

### HTTP Server - `nginx`

### FTP Server - `vsftpd`

```bash
ftp alpineftp@172.18.0.2
alpineftp
passive # need to download files
```

### SMB Server - `samba`

```bash
smbclient -U lucas%pass -L \\172.18.0.2
smbclient -U lucas%pass \\\\172.18.0.2\\public
```

### RULESETS UTILISÉS

```
❯ ./bin/suricata-update list-enabled-sources
28/11/2024 -- 17:31:31 - <Info> -- Using data-directory /home/lucas/suricata/var/lib/suricata.
28/11/2024 -- 17:31:31 - <Info> -- Using Suricata configuration /home/lucas/suricata/etc/suricata/suricata.yaml
28/11/2024 -- 17:31:31 - <Info> -- Using /home/lucas/suricata/share/suricata/rules for Suricata provided rules.
28/11/2024 -- 17:31:31 - <Info> -- Found Suricata version 8.0.0-dev at ./bin/suricata.
Enabled sources:
  - tgreen/hunting
  - malsilo/win-malware
  - stamus/lateral
  - et/open
```
