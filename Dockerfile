FROM golang:1.22.2-alpine3.19 as build

WORKDIR /var/proxy

COPY cmd cmd
COPY internal internal
COPY pkg pkg
COPY go.mod .
COPY go.sum .

RUN go build -o main ./cmd/main.go

#=========================================================================================
FROM alpine:3.18 as production

WORKDIR /var/proxy
COPY ca.crt ca.crt
COPY ca.key ca.key
COPY --from=build /var/proxy/main main

EXPOSE 8080

ENTRYPOINT ./main