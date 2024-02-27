package main

import (
	"log"
	"os"

	"github.com/Vilinvil/hw-security-1/internal/config"
	"github.com/Vilinvil/hw-security-1/internal/proxyserver"
)

func main() {
	config, err := config.New()
	if err != nil {
		log.Println(err)

		os.Exit(1)
	}

	server := new(proxyserver.ProxyServer)
	if err := server.Run(config); err != nil {

	}
}
