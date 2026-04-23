## If using External Drive (Run this at root folder at first)
find . -name "._*" -delete

## Run Build
docker-compose up --build

## Attacker

### To find app container ip  
ping ai_ids_app

### Terminal 1 (for capture) (workaround for macos)
docker exec -it attacker bash  
tcpdump -i eth0 -w /logs/attack.pcap

### Terminal 2 (for attacking)
docker exec -it attacker bash  
hping3 -S ai_ids_app -p 5000 --flood

## Zeek (Intrusion Detection)

docker exec -it zeek bash  
zeek -r /logs/attack.pcap -C Log::default_logdir=/logs
ls  
cat conn.log   (contains source ip, destination ip and many tcp connection)