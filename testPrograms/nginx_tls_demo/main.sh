docker build -t nginx-tls-demo .
docker run -d -p 443:443 --name nginx-tls nginx-tls-demo

# curl -k https://localhost