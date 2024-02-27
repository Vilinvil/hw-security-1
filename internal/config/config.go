package config

import (
	"fmt"
	"log"
	"strconv"
	"time"

	"github.com/Vilinvil/hw-security-1/pkg/config"
	"github.com/Vilinvil/hw-security-1/pkg/myerrors"
)

const (
	EnvPortServer  = "PORT_SERVER"
	EnvHostServer  = "HOST_SERVER"
	EnvCertFileTLS = "CERT_FILE_TLS"
	EnvKeyFileTLS  = "KEY_FILE_TLS"
	EnvModeTLS     = "MODE_TLS"

	// EnvBasicTimeout - env used for initialize all http timeouts.
	// Represents time in ms.
	EnvBasicTimeout = "BASIC_TIMEOUT"

	DefaultPortServer   = "8081"
	DefaultHostServer   = "localhost"
	DefaultCertFileTLS  = "localhost.crt"
	DefaultKeyFileTLS   = "localhost.key"
	DefaultModeTLS      = "DISABLE_TLS"
	ModeEnableTLS       = "ENABLE_TLS"
	DefaultBasicTimeout = "10"
)

type Config struct {
	PortServer   string
	HostServer   string
	CertFileTLS  string
	KeyFileTLS   string
	ModeTLS      bool
	BasicTimeout time.Duration
}

func New() (*Config, error) {
	countSecondsFromEnv := config.GetEnvStr(EnvBasicTimeout, DefaultBasicTimeout)

	countSecondsTimeout, err := strconv.Atoi(countSecondsFromEnv)
	if err != nil {
		log.Println(err)

		return nil, fmt.Errorf(myerrors.ErrTemplate, err)
	}

	modeTLS := false

	if config.GetEnvStr(EnvModeTLS, DefaultModeTLS) == ModeEnableTLS {
		modeTLS = true
	}

	return &Config{
		PortServer:   config.GetEnvStr(EnvPortServer, DefaultPortServer),
		HostServer:   config.GetEnvStr(EnvHostServer, DefaultHostServer),
		CertFileTLS:  config.GetEnvStr(EnvCertFileTLS, DefaultCertFileTLS),
		KeyFileTLS:   config.GetEnvStr(EnvKeyFileTLS, DefaultKeyFileTLS),
		ModeTLS:      modeTLS,
		BasicTimeout: time.Second * time.Duration(countSecondsTimeout),
	}, nil
}
