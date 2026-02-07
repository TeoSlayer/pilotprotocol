FROM golang:1.23-alpine AS builder

WORKDIR /app
COPY go.mod ./
RUN go mod download
COPY . .

RUN CGO_ENABLED=0 go build -o /rendezvous ./cmd/rendezvous
RUN CGO_ENABLED=0 go build -o /pilotctl ./cmd/pilotctl

FROM alpine:3.19
RUN apk add --no-cache ca-certificates

COPY --from=builder /rendezvous /usr/local/bin/rendezvous
COPY --from=builder /pilotctl /usr/local/bin/pilotctl

EXPOSE 9000/tcp 9001/udp

ENTRYPOINT ["rendezvous"]
