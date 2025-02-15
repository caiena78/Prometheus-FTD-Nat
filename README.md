# Cisco FTD custom Nat Poller for Prometheus

## Description
This poller runs as a web server with basic webaut enabled, from Premetheus you call this http://(FQDN):3000/metrics?target=(FTD IPaddress). 
you login to the website with the user and password you want the poller to use to connect to the Cisco FTD


## Docker install
docker build -t Prometheus-FTD-Nat .
docker run -p 3000:3000 your-image-name