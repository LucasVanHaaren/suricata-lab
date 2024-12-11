# Projet Suricata

Lucas VAN HAAREN

> [!info]
> Toutes les sources utilisées pour la réalisation de ce projet sont consultables sur ce projet Github
> https://github.com/LucasVanHaaren/suricata-lab.
>

---

```table-of-contents
title: 
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 0 # Include headings up to the specified level
includeLinks: true # Make headings clickable
hideWhenEmpty: false # Hide TOC if no headings are found
debugInConsole: false # Print debug info in Obsidian console
```

<div class="page-break" style="page-break-before: always;"></div>

# 1. Analyse de l'influence de la perte de paquets
---
## Création du lab

Le lab que j'ai conçu s'articule autour d'une stack docker-compose, déployant plusieurs conteneurs avec des services sur des protocoles différents : 
- **FTP** via `vsftpd`
- **HTTP** via `nginx`
- **SMB** via `samba`
- **TCP** (bind shell) via `netcat`

Les 3 premiers conteneurs servent tous une meme base de fichier montée en read-only dans les conteneurs. Cette base de fichiers contient des samples inoffensifs de tout type et toute taille mais également des outils offensifs et payloads malveillants dont la signature est connue (impacket, mimikatz, linpeas, agent ligolo-ng, ...).

Un conteneur client interagit avec chaque service, et pour chaque service télécharge une liste de fichiers (par défaut tous les fichiers dans le dossier `assets`). Ce conteneur client effectue également des actions malveillantes sur la machine exposant un bind shell.

Voici le fichier `docker-compose.yml` : 

```yml
services:
# ----------------------------------------------
# EXPOSE FILES FROM ./assets 
# ----------------------------------------------
  nginx:
    image: nginx
    volumes:
      - ./nginx/default.conf:/etc/nginx/conf.d/default.conf
      - ./assets/:/usr/share/nginx/static/

  ftpd:
    image: delfer/alpine-ftp-server
    volumes:
      - ./assets/:/ftp/alpineftp/
  
  smb:
    image: dperson/samba
    ports:
      - 139:139
      - 445:445
    environment:
      USER: "lucas;pass"
      SHARE: "public;/share"
    volumes:
      - ./assets/:/share

# ----------------------------------------------
# EXPOSE TCP BIND SHELL (mimic compromised host)
# ----------------------------------------------
  bindshell:
    image: busybox
    command: ["/bin/sh", "-c", "/bin/nc -lvnp 1337 -e /bin/sh"]

# ----------------------------------------------
# CLIENT TO CONNECT TO SERVICES ABOVE
# ----------------------------------------------
  client:
    image: alpine
    command: ["/bin/sh", "/scripts/entrypoint.sh"]
    volumes:
      - ./client/:/scripts
```
## Capture réseau

Le lab étant entièrement conteneurisé, il me suffit de démarrer ce dernier et commencer une capture sur l'interface du bridge docker crée pour la stack docker-compose :

```bash
❯ docker compose up -d
```

J'obtient un fichier pcap de 603Mo : 

```bash
❯ du -h samples/base_capture.pcap
603M	samples/base_capture.pcap
```

## Simulation de perte de paquets

Pour analyser l'influence de la perte de paquets pour suricata, nous devons simuler cette perte sur notre pcap source fraîchement obtenu.

J'ai choisis pour cela de coder un script python basé sur la lib `scapy` qui permet de manipuler facilement des fichiers pcap :

```python
import os
import random
import sys
from scapy.all import rdpcap, wrpcap

ITERATIONS = 3

"""
	Takes pcap sample and generate X iterations of packet loss simulation for a certain percentage
"""
def packet_loss(file_path, output_dir, percentages, iterations):
    # first : read the whole source pcap and compute packet number
    packets = rdpcap(file_path)
    total_packets = len(packets)
    base_name = os.path.basename(file_path).split('.')[0]
	
	# make sure output dir exists 
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    for percent in percentages:
        for iteration in range(1, iterations + 1):
	        # remove random packets in pcap
            num_packets_to_remove = int(total_packets * (percent / 100))
            packets_to_remove = random.sample(range(total_packets), num_packets_to_remove)
            new_packets = [pkt for i, pkt in enumerate(packets) if i not in packets_to_remove]
            # write new pcap with randomly lost packets
            output_file = os.path.join(output_dir, f"{base_name}/{percent}/{iteration}.pcap")
            os.makedirs(os.path.dirname(output_file), exist_ok=True)
            wrpcap(output_file, new_packets)
            print(f"Saved {percent}% packet loss iteration {iteration} in \t{output_file}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python gen_packet_lost.py <input_pcap> <output_directory>")
        sys.exit(1)

    input_pcap = sys.argv[1]
    output_directory = sys.argv[2]
    loss_percentages = [0.5, 1, 1.5, 2, 5, 10, 25, 50]
    print("Packet loss generation ...")
    packet_loss(input_pcap, output_directory, loss_percentages, ITERATIONS)
    print("Done!")

```

Je crée simplement un venv python et j'execute mon script python à la racine de mon projet : 

```bash
❯ python3 -m venv .venv
❯ .venv/bin/pip install scapy
❯ .venv/bin/python gen_packet_loss.py samples/base_capture.pcap samples/
Packet loss generation ...
Saved 0.5% packet loss iteration 1 in samples/base_capture/0.5/1.pcap
Saved 0.5% packet loss iteration 2 in samples/base_capture/0.5/2.pcap
Saved 0.5% packet loss iteration 3 in samples/base_capture/0.5/3.pcap
Saved 1% packet loss iteration 1 in   samples/base_capture/1/1.pcap
Saved 1% packet loss iteration 2 in   samples/base_capture/1/2.pcap
Saved 1% packet loss iteration 3 in   samples/base_capture/1/3.pcap
Saved 1.5% packet loss iteration 1 in samples/base_capture/1.5/1.pcap
Saved 1.5% packet loss iteration 2 in samples/base_capture/1.5/2.pcap
Saved 1.5% packet loss iteration 3 in samples/base_capture/1.5/3.pcap
Saved 2% packet loss iteration 1 in   samples/base_capture/2/1.pcap
Saved 2% packet loss iteration 2 in   samples/base_capture/2/2.pcap
Saved 2% packet loss iteration 3 in   samples/base_capture/2/3.pcap
Saved 5% packet loss iteration 1 in   samples/base_capture/5/1.pcap
Saved 5% packet loss iteration 2 in   samples/base_capture/5/2.pcap
Saved 5% packet loss iteration 3 in   samples/base_capture/5/3.pcap
Saved 10% packet loss iteration 1 in  samples/base_capture/10/1.pcap
Saved 10% packet loss iteration 2 in  samples/base_capture/10/2.pcap
Saved 10% packet loss iteration 3 in  samples/base_capture/10/3.pcap
Saved 25% packet loss iteration 1 in  samples/base_capture/25/1.pcap
Saved 25% packet loss iteration 2 in  samples/base_capture/25/2.pcap
Saved 25% packet loss iteration 3 in  samples/base_capture/25/3.pcap
Saved 50% packet loss iteration 1 in  samples/base_capture/50/1.pcap
Saved 50% packet loss iteration 2 in  samples/base_capture/50/2.pcap
Saved 50% packet loss iteration 3 in  samples/base_capture/50/3.pcap
Done!
```

J'obtiens alors cette hiérarchie de fichiers dans mon dossier `samples` :

```
❯ tree samples/
samples/
├── base_capture
│   ├── 0.5
│   │   ├── 1.pcap
│   │   ├── 2.pcap
│   │   └── 3.pcap
│   ├── 1
│   │   ├── 1.pcap
│   │   ├── 2.pcap
│   │   └── 3.pcap
│   ├── 10
│   │   ├── 1.pcap
│   │   ├── 2.pcap
│   │   └── 3.pcap
│   ├── 1.5
│   │   ├── 1.pcap
│   │   ├── 2.pcap
│   │   └── 3.pcap
│   ├── 2
│   │   ├── 1.pcap
│   │   ├── 2.pcap
│   │   └── 3.pcap
│   ├── 25
│   │   ├── 1.pcap
│   │   ├── 2.pcap
│   │   └── 3.pcap
│   ├── 5
│   │   ├── 1.pcap
│   │   ├── 2.pcap
│   │   └── 3.pcap
│   └── 50
│       ├── 1.pcap
│       ├── 2.pcap
│       └── 3.pcap
└── base_capture.pcap

10 directories, 25 files
```

## Configuration de suricata

Une fois toutes les captures prêtes a être analysées, il faut configurer suricata de manière a produire des résultat intéressants :
- activer le filestore (pour analyser le nombre de fichier récupérés)
- activer des rulesets produisant des alertes intéressantes

La configuration du filestore est triviale puisqu'il s'agit de dé-commenter ces lignes dans le fichier de config `suricata.yaml` : 

```yaml
outputs:
- file-store:
	version: 2
	enabled: yes
	force-filestore: yes
	stream-depth: 0
```

On active les différents rulesets via le helper `suricata-update` : 

```bash
❯ suricata-update list-sources
❯ suricata-update enable-source et/open
❯ suricata-update enable-source stamus/lateral
❯ suricata-update enable-source malsilo/win-malware
❯ suricata-update enable-source tgreen/hunting
❯ suricata-update
```

=> Les rulesets ont été choisi en réalisant quelques runs de suricata sur le sample de base avec un maximum de pack de règles, puis j'ai conservé celles étant les plus intéressantes.

## Bancs de tests

Je commence par créer une baseline en lancant suricata sur le pcap de base sans perte de packet simulée :

```bash
suricata -r samples/base_capture.pcap -l analysis/ -k none -v --runmode=single
```

- l'option `-k none` permet de ne pas prendre en compte les erreurs de checksums sur une capture locale
- l'option `--runmode=single` permet de stabiliser les résultats de suricata en précisant de réaliser le traitement sur un seul thread

Pour réaliser les différents tests, j'ai choisis de coder un script bash qui permet de lancer suricata sur chaque fichier pcap, puis de sortir un output pour chaque pcap :

```bash
#!/bin/bash

# Define the source and destination directories
SOURCE_DIR="./samples/base_capture"
DEST_DIR="./analysis/"

# Create the destination directory if it doesn't exist
mkdir -p "$DEST_DIR"

# Loop through each pcap file in the source directory
for pcap_file in "$SOURCE_DIR"/*.pcap; do
    # Get the base name of the pcap file (without the directory and extension)
    base_name=$(basename "$pcap_file" .pcap)
    
    # Create a destination folder with the same name as the pcap file
    dest_folder="$DEST_DIR/$base_name"
    mkdir -p "$dest_folder"
    
    # Run suricata on the pcap file and output to the destination folder
    suricata -r "$pcap_file" -l "$dest_folder" -k none -v --runmode=single
done
```

Ce script tire simplement parti de la hiérarchie de fichiers crée par le script `gen_packet_loss.py` pour itérer et lancer suricata sur sur chaque pcap de chaque dossier dans `samples`.

On obtient alors cette hiérarchie de fichiers dans le dossier `analysis` :

```
analysis/
├── 0
│   ├── 1
│   │   ├── eve.json
│   │   ├── fast.log
│   │   ├── filestore
│   │   ├── stats.log
│   │   └── suricata.log
│   ├── 2
│   │   ├── eve.json
│   │   ├── fast.log
│   │   ├── filestore
│   │   ├── stats.log
│   │   └── suricata.log
│   └── 3
│       ├── eve.json
│       ├── fast.log
│       ├── filestore
│       ├── stats.log
│       └── suricata.log
├── 0.5
│   ├── 1
│   │   ├── eve.json
│   │   ├── fast.log
│   │   ├── filestore
│   │   ├── stats.log
│   │   └── suricata.log
│   ├── 2
│   │   ├── eve.json
│   │   ├── fast.log
│   │   ├── filestore
│   │   ├── stats.log
│   │   └── suricata.log
│   └── 3
│       ├── eve.json
│       ├── fast.log
│       ├── filestore
│       ├── stats.log
│       └── suricata.log
...
```

## Analyse des résultats

Une fois les outputs obtenus pour chaque sample pcap, nous pouvons réaliser une analyse sur les 3 points suivants :
  - nombre de transactions protocolaires
  - nombre d'alertes levées
  - nombre de fichiers extraits

Pour simplifier l'analyse, j'ai choisi de coder un script en bash, qui va parcourir les outputs dans le dossier `analysis` et réaliser pour chaque pourcentage donné une moyenne des différents points sur les 3 itérations, puis de stocker cela dans un fichier csv :

```bash
#!/bin/bash

# Define the analysis folder
analysis_folder="analysis"
# Define the output CSV file
output_csv="analysis_summary.csv"
# Define a temporary file for storing intermediate results
temp_file="temp_analysis.csv"

# Write the CSV header
echo "Subfolder,Alerts,Filestore files,Protocol transactions" > "$output_csv"

# Loop through each subfolder in the analysis folder
for subfolder in "$analysis_folder"/*/; do
    # Loop through each pcap analysis folder in the current subfolder
    for pcap_folder in "$subfolder"/*/; do
        # Define the log file path
        log_file="$pcap_folder/suricata.log"
        
        # Initialize variables
        alert_count=0
        file_count=0
        protocol_transactions=0
        
        # Check if the log file exists
        if [[ -f "$log_file" ]]; then
            # Extract the number of alerts from the specified line format
            alert_count=$(grep "counters: Alerts:" "$log_file" | awk -F'Alerts: ' '{print $2}')
        fi

        # Check if the filestore subfolder exists
        if [[ -d "$pcap_folder/filestore" ]]; then
            # Count the number of files in the filestore subfolder
            file_count=$(find "$pcap_folder/filestore" -type f | wc -l)
        fi

        # Check if the eve.json file exists
        if [[ -f "$pcap_folder/eve.json" ]]; then
            # Parse the number of protocol transactions
            protocol_transactions=$(cat "$pcap_folder/eve.json" | jq -r '. | select(.event_type == "smb" or .event_type == "http" or .event_type == "ftp" or .event_type == "tcp") | .event_type' | sort | uniq -c | awk '{sum += $1} END {print sum}')
        fi
        
        # Print the subfolder name, the number of alerts, the number of files in filestore, and the number of protocol transactions
        echo "Subfolder: $(basename "$subfolder")/$(basename "$pcap_folder"), Alerts: $alert_count, Filestore files: $file_count, Protocol transactions: $protocol_transactions"
        
        # Append the data to the temporary file
        echo "$(basename "$subfolder")/$(basename "$pcap_folder"),$alert_count,$file_count,$protocol_transactions" >> "$temp_file"
    done
done

# Function to compute the median
compute_median() {
    arr=($(printf '%s\n' "$@" | sort -n))
    len=${#arr[@]}
    if (( $len % 2 == 1 )); then
        echo "${arr[$((len/2))]}"
    else
        echo $(( (arr[len/2-1] + arr[len/2]) / 2 ))
    fi
}

# Compute the median for each base_capture_X group
for base in $(awk -F'/' '{print $1}' "$temp_file" | sort | uniq); do
    alerts=($(grep "^$base" "$temp_file" | awk -F',' '{print $2}'))
    files=($(grep "^$base" "$temp_file" | awk -F',' '{print $3}'))
    transactions=($(grep "^$base" "$temp_file" | awk -F',' '{print $4}'))
    
    median_alerts=$(compute_median "${alerts[@]}")
    median_files=$(compute_median "${files[@]}")
    median_transactions=$(compute_median "${transactions[@]}")
    
    echo "$base,$median_alerts,$median_files,$median_transactions" >> "$output_csv"
done

# Clean up the temporary file
rm "$temp_file"
```

On lance le script :
```bash
❯ bash analyse_suricata_outputs.sh
Subfolder: 0/1, Alerts: 198, Filestore files: 0, Protocol transactions: 150
Subfolder: 0/2, Alerts: 198, Filestore files: 0, Protocol transactions: 150
Subfolder: 0/3, Alerts: 198, Filestore files: 0, Protocol transactions: 150
Subfolder: 0.5/1, Alerts: 220, Filestore files: 0, Protocol transactions: 91
Subfolder: 0.5/2, Alerts: 215, Filestore files: 0, Protocol transactions: 150
Subfolder: 0.5/3, Alerts: 232, Filestore files: 0, Protocol transactions: 113
Subfolder: 1/1, Alerts: 243, Filestore files: 0, Protocol transactions: 85
Subfolder: 1/2, Alerts: 207, Filestore files: 0, Protocol transactions: 149
Subfolder: 1/3, Alerts: 185, Filestore files: 0, Protocol transactions: 126
Subfolder: 10/1, Alerts: 232, Filestore files: 0, Protocol transactions: 41
Subfolder: 10/2, Alerts: 281, Filestore files: 0, Protocol transactions: 45
Subfolder: 10/3, Alerts: 275, Filestore files: 0, Protocol transactions: 47
Subfolder: 1.5/1, Alerts: 263, Filestore files: 0, Protocol transactions: 84
Subfolder: 1.5/2, Alerts: 259, Filestore files: 0, Protocol transactions: 101
Subfolder: 1.5/3, Alerts: 263, Filestore files: 0, Protocol transactions: 104
Subfolder: 2/1, Alerts: 249, Filestore files: 0, Protocol transactions: 88
Subfolder: 2/2, Alerts: 264, Filestore files: 0, Protocol transactions: 78
Subfolder: 2/3, Alerts: 298, Filestore files: 0, Protocol transactions: 80
Subfolder: 25/1, Alerts: 221, Filestore files: 0, Protocol transactions: 19
Subfolder: 25/2, Alerts: 228, Filestore files: 0, Protocol transactions: 37
Subfolder: 25/3, Alerts: 240, Filestore files: 0, Protocol transactions: 27
Subfolder: 5/1, Alerts: 307, Filestore files: 0, Protocol transactions: 57
Subfolder: 5/2, Alerts: 257, Filestore files: 0, Protocol transactions: 72
Subfolder: 5/3, Alerts: 269, Filestore files: 0, Protocol transactions: 64
Subfolder: 50/1, Alerts: 177, Filestore files: 0, Protocol transactions: 10
Subfolder: 50/2, Alerts: 131, Filestore files: 0, Protocol transactions: 8
Subfolder: 50/3, Alerts: 94, Filestore files: 0, Protocol transactions: 15
```

On obtient ce fichier csv avec les données :

```csv
Subfolder,Alerts,Filestore files,Protocol transactions
0,206,10,150
0.5,220,27,113
1,259,20,85
1.5,263,23,101
2,244,15,57
5,217,8,36
10,275,12,45
25,228,10,27
50,131,3,10
```

Pour représenter cela de façon visuelle j'ai choisi de créer un petit script avec l'outil `gnuplot` :

```
set datafile separator ","
set terminal png size 800,600
set output 'analysis_summary.png'

set title "Suricata Analysis Summary"
set xlabel "Subfolder"
set ylabel "Count"
set grid

set style data linespoints

plot "analysis_summary.csv" using 2:xtic(1) title "Alerts" with linespoints, \
     "analysis_summary.csv" using 3:xtic(1) title "Filestore files" with linespoints, \
     "analysis_summary.csv" using 4:xtic(1) title "Protocol transactions" with linespoints
```

On obtient alors ce graph :

![[analysis_summary.png]]

## Interprétation des résultats

- le **nombres d'alertes** devient incohérent aux environs des 5% de perte de paquets, on observe sur le graph un pic juste après les 5% puis une chute en dessous de la baseline après 25%
- le nombre de transactions protocolaires chute de manière quasi linéaire comme on pourrai s'y attendre
- le nombre de fichiers récupérés suit également une courbe descendante linéaire 

Pour conclure, l’analyse des données met en évidence différents impacts selon les métriques étudiées. D’une part, le **nombre d’alertes** présente une dynamique non linéaire avec des résultats incohérents juste après 5% de perte de paquets, suivi d'une nette chute en dessous de la baseline au-delà de 25%. Ce comportement que l'on pouvais attendre suggère une perte d'efficacité du système de détection dans ces conditions. D’autre part, les **transactions protocolaires** et le **nombre de fichiers récupérés** suivent une tendance descendante linéaire, en cohérence avec les attentes face à une dégradation progressive des captures réseau.

<div class="page-break" style="page-break-before: always;"></div>

# 2. Détection en périphérie
---

## Création du lab

Le lab que j'ai conçu s'articule autour d'une stack docker-compose, déployant plusieurs conteneurs visant à simuler un réseau de périphérie, composé de : 
- **reverse-proxy** avec `nginx` (considéré comme membre du groupe `IP_GW`) => configuré en proxy-pass vers les 2 conteneurs suivants
- **web-a** et **web-b** avec `nginx` => sites web statiques 

Le réseau bridge crée par la stack docker compose sera donc considéré comme `HOME_NET` puisqu'il simule un réseau interne. Il a pour adresse de réseau `192.168.20.0/24`.
Le conteneur reverse-proxy à pour IP `192.168.20.10` et les 2 conteneurs web ont pour IP respectives `192.168.20.20` et `192.168.20.30`.

Mon système hôte jouera le role de client légitime, puis des actions locales au conteneur simulerons une compromission de l'équipement de périphérie.

Voici le fichier `docker-compose.yml` :

```yml
services:
  reverse-proxy:
    image: nginx
    volumes:
      - ./reverse-proxy/default.conf:/etc/nginx/conf.d/default.conf
    ports:
      - 8080:80
    depends_on:
    - web-a
    - web-b
    networks:
      vpcbr:
        ipv4_address: 192.168.20.10

  web-a:
    image: nginx
    networks:
      vpcbr:
        ipv4_address: 192.168.20.20

  web-b:
    image: nginx
    networks:
      vpcbr:
        ipv4_address: 192.168.20.30
  
networks:
  vpcbr:
    driver: bridge
    ipam:
      config:
      - subnet: 192.168.20.0/24
        gateway: 192.168.20.1
```

## Détections des connexions de `IP_GW` vers internet

Avant toute création de signature, je configure certaines variables dans le fichier `suricata.yaml` : 

```yaml
vars:
  address-groups:
    HOME_NET: "[192.168.20.0/24]"
    EXTERNAL_NET: "!$HOME_NET"
	IP_GW: "[192.168.20.10]"
```

- `HOME_NET` => correspond a tout le réseau interne docker
- `EXTERNAL_NET` => correspond à tout ce qui est en dehors du réseau `HOME_NET`
- `IP_GW` => correspond à l'IP du reverse-proxy nginx

Voici la règle qui a été crée pour détecter les connexions depuis les machines `IP_GW` vers des machines `EXTERNAL_NET` :

```
alert ip $IP_GW any -> $EXTERNAL_NET any (msg:"MSSIS Connexion de IP_GW vers EXTERNAL_NET";
	sid:1; rev:1;)
```

On lance suricata, puis on réalise des actions telles que le mise à jour ses dépôts de paquets système et on lance un ping sur le DNS cloudflare, et on obtient l'output suivant :

```bash
❯ suricata -S ./rules/1.rules -r ./sample.pcap -k none -v -l data/
❯ cat data/eve.json | jq -r 'select(.event_type=="alert").dest_ip' | sort -u
1.1.1.1
192.168.1.1
199.232.170.132
```

## Alertes lors de connexions vers des IP inconnues sur internet

L'objectif ici étant de lever une alerte uniquement pour les nouvelles IP jointe sur internet depuis les machines `IP_GW`, il faut donc maintenir une listes des IPs connues.

- Pour cela nous utilisons un dataset suricata, mais avant tout il faut penser à l'activer dans le fichier de configuration `suricata.yaml` :

```yml
datasets:
  defaults:
    memcap: 100 MiB
	hashsize: 2048
```

- On crée ensuite une première signature qui va enregistrer toutes les IPs dans le dataset :

```
alert ip $IP_GW any -> $EXTERNAL_NET any (msg:"MSSIS Nouvelle connexion de IP_GW vers EXTERNAL_NET"; \
  ip.dst; dataset:set,ip,type ipv4,state known_ips_set.txt ; \
  sid:2; rev:1;)
```

- On va ensuite simuler une phase d'apprentissage sur la meme capture que l'on a utilisé ci-dessus :

```bash
❯ suricata -S ./rules/2.rules -r ./sample.pcap -k none -v -l data/
Notice: suricata: This is Suricata version 8.0.0-dev (a9b36d88b 2024-12-05) running in USER mode [LogVersion:suricata.c:1151]
[...]
Notice: pcap: read 1 file, 111 packets, 110119 bytes [ReceivePcapFileThreadExitStats:source-pcap-file.c:413]
Info: counters: Alerts: 3 [StatsLogSummary:counters.c:868]
```

- On retrouve bien dans le dataset les 3 IP jointes lors de la capture :

```bash
❯ cat known_ips_set.txt
192.168.1.1
1.1.1.1
199.232.170.132
```

- Une fois notre dataset avec les IPs "de confiance", on crée une seconde signature qui va lever une alerte si une connexion est effectuée vers une IP qui n'est pas dans le dataset :

```bash
alert ip $IP_GW any -> $EXTERNAL_NET any (msg:"MSSIS Connexion de IP_GW vers une IP inconnue dans EXTERNAL_NET"; \
  ip.dst; dataset:isnotset,ip,type ipv4,state known_ips_set.txt ; \
  sid:2; rev:1;)
```

- On peut ensuite s'assurer que cela fonctionne en relançant sur la meme capture réseau :

```bash
❯ suricata -S ./rules/3.rules -r ./sample.pcap -k none -v -l data/
Notice: suricata: This is Suricata version 8.0.0-dev (a9b36d88b 2024-12-05) running in USER mode [LogVersion:suricata.c:1151]
[...]
Notice: pcap: read 1 file, 111 packets, 110119 bytes [ReceivePcapFileThreadExitStats:source-pcap-file.c:413]
Info: counters: Alerts: 0 [StatsLogSummary:counters.c:868]
```

Aucune alerte n'est levée ici car les IPs jointes sont toutes déjà connues.

- Pour valider la signature on teste en live la connexion vers des IPs non connues :

```bash
❯ sudo suricata -S ./rules/3.rules -i br-2427e506dfd7 -k none -v -l data/
```

- On pop un shell dans le conteneur reverse-proxy, puis on crée des connexions a ces 3 IPs : `1.1.1.1`, `8.8.8.8`, `1.2.3.4`

```bash
❯ docker compose exec -it reverse-proxy bash
root@75f004717876:/# ping -c 3 8.8.8.8
PING 8.8.8.8 (8.8.8.8) 56(84) bytes of data.
64 bytes from 8.8.8.8: icmp_seq=1 ttl=114 time=2.44 ms
64 bytes from 8.8.8.8: icmp_seq=2 ttl=114 time=2.23 ms
64 bytes from 8.8.8.8: icmp_seq=3 ttl=114 time=2.51 ms
--- 8.8.8.8 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2002ms
rtt min/avg/max/mdev = 2.230/2.393/2.506/0.118 ms

root@75f004717876:/# ping -c4 1.2.3.4
PING 1.2.3.4 (1.2.3.4) 56(84) bytes of data.
--- 1.2.3.4 ping statistics ---
4 packets transmitted, 0 received, 100% packet loss, time 3033ms

root@75f004717876:/# ping -c 3 1.1.1.1
PING 1.1.1.1 (1.1.1.1) 56(84) bytes of data.
64 bytes from 1.1.1.1: icmp_seq=1 ttl=63 time=1.19 ms
64 bytes from 1.1.1.1: icmp_seq=2 ttl=63 time=0.732 ms
64 bytes from 1.1.1.1: icmp_seq=3 ttl=63 time=0.929 ms
--- 1.1.1.1 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2026ms
rtt min/avg/max/mdev = 0.732/0.949/1.187/0.186 ms
```

- On observe dans l'output que seul les 2 IPs `8.8.8.8`, et `1.2.3.4` ont levés des alertes :

```bash
❯ cat data/eve.json | jq 'select(.alert).dest_ip'
"8.8.8.8"
"8.8.8.8"
"8.8.8.8"
"1.2.3.4"
"1.2.3.4"
"1.2.3.4"
"1.2.3.4"
```

## Détection de l'utilisation de nouveaux protocoles par les `IP_GW`

Après beaucoup de recherche et de lecture de la documentation, il ne semble pas possible de faire ce genre de règle car pour le moment il n'existe aucun moyen d'utiliser le protocole applicatif décodé dans un dataset.

Si cela était possible, nous pourrions faire comme pour les IP et maintenir un dataset de protocoles connus et considérés comme légitimes, puis lever une alerte lorsque le protocole utilisé n'est pas dans cette liste.

## Générations de signatures sur les métadonnées HTTPS

L'objectif ici est de générer rapidement un ensemble de règle alertant sur ces éléments :
 - les user agent HTTP
 - les empreintes ja4 TLS
 - les noms sni TLS et Host HTTP (en un seul dataset)****
 - les IP destinations sur internet (hors protocoles HTTP et TLS)

- Je commence donc par écrire un script python qui va simplement contenir le templates de mes alertes, puis permettre de définir l'IP source en ligne de commande : 

```python
import sys

if len(sys.argv) != 2:
    print("Usage: python generator.py <IP_GW>")
    sys.exit(1)

IP_GW = sys.argv[1]
RULESET_NAME = "mssis.rules"

# rules templates
RULES = [
    # detect unknown HTTP User-Agent
    f"""alert http {IP_GW} any -> any any (msg:"MSSIS Connection from unknown HTTP User-Agent"; \\
        http.user_agent; dataset:set,ua, type string, state {IP_GW.replace('.','_')}_ua.txt; \\
        sid:1; rev:1;)""",
    # detect unknown TLS JA4
    f"""alert tls {IP_GW} any -> any any (msg:"MSSIS Connection with unknown TLS JA4"; \\
        ja4.hash; dataset:set,ja4, type string, state {IP_GW.replace('.','_')}_ja4.txt; \\
        sid:2; rev:1;)""",
    # detect unknown HTTP Host
    f"""alert http {IP_GW} any -> any any (msg:"MSSIS Connection with unknown HTTP Host"; \\
        http.host; dataset:set,host, type string, state {IP_GW.replace('.','_')}_host_sni.txt; \\
        sid:3; rev:1;)""",
    # detect unknown TLS SNI
    f"""alert tls {IP_GW} any -> any any (msg:"MSSIS Connection with unknown TLS SNI"; \\
        tls.sni; dataset:set,sni, type string, state {IP_GW.replace('.', '_')}_host_sni.txt; \\
        sid:4; rev:1;)""",
    # detect dest IP on internet when proto is not HTTP or TLS
    f"""pass http {IP_GW} any -> any any (msg:"MSSIS pass HTTP"; \\
        sid:5; rev:1;)""",
    f"""pass tls {IP_GW} any -> any any (msg:"MSSIS pass TLS"; \\
        sid:6; rev:1;)""",
    f"""alert ip {IP_GW} any -> $EXTERNAL_NET any (msg:"MSSIS Connection to unknown "; \\
        ip.dst; dataset:set,ip, type ipv4, state {IP_GW.replace('.', '_')}_external_ips_not_http_tls.txt; \\
        sid:7; rev:1;)"""
]

# dump rules to file
with open(RULESET_NAME, "w") as f:
    f.write("# MSSIS autogenerated rules\n")
    for rule in RULES:
        f.write(rule + "\n")
```

- On lance le script avec en argument l'IP de mon reverse-proxy : 

```bash
❯ python rules/generator.py 192.168.20.10
❯ cat mssis.rules
# MSSIS autogenerated rules
alert http 192.168.20.10 any -> any any (msg:"MSSIS Connection from unknown HTTP User-Agent"; \
        http.user_agent; dataset:set,ua, type string, state 192_168_20_10_ua.txt; \
        sid:1; rev:1;)
alert tls 192.168.20.10 any -> any any (msg:"MSSIS Connection with unknown TLS JA4"; \
        ja4.hash; dataset:set,ja4, type string, state 192_168_20_10_ja4.txt; \
        sid:2; rev:1;)
alert http 192.168.20.10 any -> any any (msg:"MSSIS Connection with unknown HTTP Host"; \
        http.host; dataset:set,host, type string, state 192_168_20_10_host_sni.txt; \
        sid:3; rev:1;)
alert tls 192.168.20.10 any -> any any (msg:"MSSIS Connection with unknown TLS SNI"; \
        tls.sni; dataset:set,sni, type string, state 192_168_20_10_host_sni.txt; \
        sid:4; rev:1;)
pass http 192.168.20.10 any -> any any (msg:"MSSIS pass HTTP"; \
        sid:5; rev:1;)
pass tls 192.168.20.10 any -> any any (msg:"MSSIS pass TLS"; \
        sid:6; rev:1;)
alert ip 192.168.20.10 any -> $EXTERNAL_NET any (msg:"MSSIS Connection to unknown "; \
        ip.dst; dataset:set,ip, type ipv4, state 192_168_20_10_external_ips_not_http_tls.txt; \
        sid:7; rev:1;)
```

On obtient bien les règles que l'on souhaite.

- On peut désormais tester ces règles sur notre PCAP :

```bash
❯ for LINE in `cat 192_168_20_10_ua.txt`; do echo $LINE | base64 -d; echo "";  done
Debian APT-HTTP/1.3 (2.6.1)
Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0

❯ for LINE in `cat 192_168_20_10_host_sni.txt`; do echo $LINE | base64 -d; echo "";  done
web-a
web-b
deb.debian.org
```

## Conclusion

Suricata permet de rapidement mettre en place un détection de comportements déviants (IP/protocoles inconnues) pour assurer une sécurité de base pour des équipements de périphérie tels que les reverse-proxy et gateway VPN. Il est également possible de renforcer cette détection via des règles plus poussées portant sur des métadonnées, le tout en automatisant ce procesuss - ici un simple script python mais l'on pourrai imaginer un playbook Ansible qui va automatiquement créer de nouvelles règles, alimenter un dataset d'éléments de confiance, etc ...).
