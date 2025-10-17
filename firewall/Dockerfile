FROM golang:1.25-alpine

RUN apk add --no-cache iptables

WORKDIR /app
COPY . .
RUN go build -o firewall .
CMD ["./entrypoint.sh"]

EXPOSE 8080