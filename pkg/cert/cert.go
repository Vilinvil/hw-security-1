package cert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"log"
	"math/big"
	"time"

	"github.com/Vilinvil/hw-security-1/pkg/myerrors"
)

const (
	leafMaxAge = 24 * time.Hour
	caUsage    = x509.KeyUsageDigitalSignature |
		x509.KeyUsageContentCommitment |
		x509.KeyUsageKeyEncipherment |
		x509.KeyUsageDataEncipherment |
		x509.KeyUsageKeyAgreement |
		x509.KeyUsageCertSign |
		x509.KeyUsageCRLSign
	leafUsage = caUsage
)

var ErrCertCA = myerrors.NewError("CA cert is not a CA")

func GenCert(certCA *tls.Certificate, names []string) (*tls.Certificate, error) {
	now := time.Now().Add(-1 * time.Hour).UTC()

	if !certCA.Leaf.IsCA {
		log.Println(ErrCertCA)

		return nil, ErrCertCA
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)

	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Println(err)

		return nil, fmt.Errorf(myerrors.ErrTemplate, err)
	}

	tmpl := &x509.Certificate{ //nolint:exhaustruct
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{CommonName: names[0]}, //nolint:exhaustruct
		NotBefore:             now,
		NotAfter:              now.Add(leafMaxAge),
		KeyUsage:              leafUsage,
		BasicConstraintsValid: true,
		DNSNames:              names,
		SignatureAlgorithm:    x509.SHA512WithRSA,
	}

	// TODO до конца не понял, какой тут нужно выбирать алгоритм
	//MD2WithRSA  // Unsupported.
	//MD5WithRSA  // Only supported for signing, not verification.
	//SHA1WithRSA // Only supported for signing, and verification of CRLs, CSRs, and OCSP responses.
	//SHA256WithRSA
	//SHA384WithRSA
	//SHA512WithRSA
	//DSAWithSHA1   // Unsupported.
	//DSAWithSHA256 // Unsupported.
	//ECDSAWithSHA1 // Only supported for signing, and verification of CRLs, CSRs, and OCSP responses.
	//ECDSAWithSHA256
	//ECDSAWithSHA384
	//ECDSAWithSHA512
	//SHA256WithRSAPSS
	//SHA384WithRSAPSS
	//SHA512WithRSAPSS
	//PureEd25519

	key, err := genKeyPair()
	if err != nil {
		return nil, fmt.Errorf(myerrors.ErrTemplate, err)
	}

	CertX509, err := x509.CreateCertificate(rand.Reader, tmpl, certCA.Leaf, key.Public(), certCA.PrivateKey)
	if err != nil {
		log.Println(err)

		return nil, fmt.Errorf(myerrors.ErrTemplate, err)
	}

	cert := new(tls.Certificate)
	cert.Certificate = append(cert.Certificate, CertX509)
	cert.PrivateKey = key

	cert.Leaf, err = x509.ParseCertificate(CertX509)
	if err != nil {
		log.Println(err)

		return nil, fmt.Errorf(myerrors.ErrTemplate, err)
	}

	return cert, nil
}

func genKeyPair() (*ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		log.Println(err)

		return nil, fmt.Errorf(myerrors.ErrTemplate, err)
	}

	return key, nil
}
