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
find ./lab/assets/ -type f | sed 's/\.\/lab\/assets\///g' > ./lab/client/assets.lst
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


- Je decoupe mon pcap en rondelles :
```bash
❯ python gen_packet_loss.py samples/base_capture.pcap samples/
Packet loss generation ...
Saved 0.5% packet loss iteration 1 in 	samples/base_capture/0.5/1.pcap
Saved 0.5% packet loss iteration 2 in 	samples/base_capture/0.5/2.pcap
Saved 0.5% packet loss iteration 3 in 	samples/base_capture/0.5/3.pcap
Saved 1% packet loss iteration 1 in 	samples/base_capture/1/1.pcap
Saved 1% packet loss iteration 2 in 	samples/base_capture/1/2.pcap
Saved 1% packet loss iteration 3 in 	samples/base_capture/1/3.pcap
Saved 1.5% packet loss iteration 1 in 	samples/base_capture/1.5/1.pcap
Saved 1.5% packet loss iteration 2 in 	samples/base_capture/1.5/2.pcap
Saved 1.5% packet loss iteration 3 in 	samples/base_capture/1.5/3.pcap
Saved 2% packet loss iteration 1 in 	samples/base_capture/2/1.pcap
Saved 2% packet loss iteration 2 in 	samples/base_capture/2/2.pcap
Saved 2% packet loss iteration 3 in 	samples/base_capture/2/3.pcap
Saved 5% packet loss iteration 1 in 	samples/base_capture/5/1.pcap
Saved 5% packet loss iteration 2 in 	samples/base_capture/5/2.pcap
Saved 5% packet loss iteration 3 in 	samples/base_capture/5/3.pcap
Saved 10% packet loss iteration 1 in 	samples/base_capture/10/1.pcap
Saved 10% packet loss iteration 2 in 	samples/base_capture/10/2.pcap
Saved 10% packet loss iteration 3 in 	samples/base_capture/10/3.pcap
Saved 25% packet loss iteration 1 in 	samples/base_capture/25/1.pcap
Saved 25% packet loss iteration 2 in 	samples/base_capture/25/2.pcap
Saved 25% packet loss iteration 3 in 	samples/base_capture/25/3.pcap
Saved 50% packet loss iteration 1 in 	samples/base_capture/50/1.pcap
Saved 50% packet loss iteration 2 in 	samples/base_capture/50/2.pcap
Saved 50% packet loss iteration 3 in 	samples/base_capture/50/3.pcap
Done!
```

- je fourre ça comme rulesets :

```bash
❯ ~/suricata/bin/suricata-update list-enabled-sources
2/12/2024 -- 18:02:06 - <Info> -- Using data-directory /home/lucas/suricata/var/lib/suricata.
2/12/2024 -- 18:02:06 - <Info> -- Using Suricata configuration /home/lucas/suricata/etc/suricata/suricata.yaml
2/12/2024 -- 18:02:06 - <Info> -- Using /home/lucas/suricata/share/suricata/rules for Suricata provided rules.
2/12/2024 -- 18:02:06 - <Info> -- Found Suricata version 8.0.0-dev at /home/lucas/suricata/bin/suricata.
Enabled sources:
  - tgreen/hunting
  - malsilo/win-malware
  - stamus/lateral
  - et/open
```

```
"ET INFO SMB2 NT Create AndX Request For an Executable File"
"GPL ATTACK_RESPONSE id check returned root"
"SURICATA Applayer Protocol detection skipped"
"SURICATA STREAM ESTABLISHED invalid ack"
"SURICATA STREAM ESTABLISHED packet out of window"
"SURICATA STREAM FIN invalid ack"
"SURICATA STREAM FIN out of window"
"SURICATA STREAM Packet with invalid ack"
"TGI HUNT Possiblly Malicious PyExe Import Name (impacket)"
```

- une fois fait le pcap de base, je run mon script against le reste des mini pcap :
```
❯ bash run_suricata.sh
```
- les resultats depassent toute attentes et mon script lance un gros run de suricate sur chaque pcap pour me foutre l'output dans un subfolder de analysis

- la suite c'est faire uen analyse de ces 3 points sur chaque output de suricate :
  - nombres de transactions protocolaires
  - nombre d'alertes
  - nombre de fichier extraits



calcul du nombre de fichier extraits
```
find analysis/base_capture/filestore/ -type f | wc -l
```