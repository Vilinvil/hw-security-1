package main

import (
	"log"
	"os"

	"github.com/Vilinvil/hw-security-1/internal/config"
	"github.com/Vilinvil/hw-security-1/internal/proxyserver"
)

func main() {
	configProxyServer, err := config.New()
	if err != nil {
		log.Println(err)

		os.Exit(1)
	}

	log.SetFlags(log.Llongfile)

	server := new(proxyserver.ProxyServer)
	if err := server.Run(configProxyServer); err != nil {
		log.Println(err)
	}
}
