FROM docker.io/python:3.12-alpine3.20
LABEL maintainer="Chad Aiena"

RUN apk add --no-cache --upgrade git

RUN mkdir -p /var/python

WORKDIR /var/python

RUN git clone https://github.com/caiena78/Prometheus-FTD-Nat.git

WORKDIR /var/python/Prometheus-FTD-Nat

RUN pip3 install -r requirements.txt

EXPOSE 3000/tcp

CMD ["python3", "web.py"]