FROM golang:1.21.1-alpine3.18 as build

WORKDIR /var/proxy

RUN apk add openssl
COPY scripts/gen_cert.sh gen_cert.sh
RUN ./gen_cert.sh
COPY cmd cmd
COPY internal internal
COPY pkg pkg
COPY go.mod .
COPY go.sum .

RUN go build -o main ./cmd/main.go

#=========================================================================================
FROM alpine:3.18 as production

WORKDIR /var/proxy
COPY --from=build /var/proxy/main main
COPY --from=build /var/proxy/ca.crt ca.crt
COPY --from=build /var/proxy/ca.key ca.key

EXPOSE 8080

ENTRYPOINT ./main