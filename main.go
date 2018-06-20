package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"os"

	"github.com/jhunt/go-cli"
)

func usage(out io.Writer, rc int) {
	fmt.Fprintf(out, "USAGE: x509ck --ca ca.pem --cert cert.pem --key private.key\n")
	os.Exit(rc)
}

type Options struct {
	CA   string `cli:"-a, --ca"`
	Cert string `cli:"-c, --cert"`
	Key  string `cli:"-k, --key"`

	Help bool `cli:"-h, --help"`
}

func main() {
	var (
		err      error
		raw      []byte
		opt      Options
		ca, cert *x509.Certificate
		key      *rsa.PrivateKey
	)

	_, args, err := cli.Parse(&opt)
	if err != nil {
		fmt.Fprintf(os.Stderr, "!!! %s\n", err)
		os.Exit(1)
	}

	if len(args) != 0 {
		usage(os.Stderr, 1)
	}

	if opt.Help {
		usage(os.Stdout, 0)
	}

	if opt.Cert == "" || opt.Key == "" {
		usage(os.Stderr, 1)
	}

	if opt.CA != "" {
		raw, err = ioutil.ReadFile(opt.CA)
		if err != nil {
			fmt.Fprintf(os.Stderr, "certificate authority '%s': %s\n", opt.CA, err)
			os.Exit(2)
		}

		block, _ := pem.Decode(raw)
		if block == nil {
			fmt.Fprintf(os.Stderr, "certificate authority '%s': not a valid PEM file\n", opt.CA)
			os.Exit(2)
		}
		if block.Type != "CERTIFICATE" {
			fmt.Fprintf(os.Stderr, "certificate authority '%s': not a certificate\n", opt.CA)
			os.Exit(2)
		}
		ca, err = x509.ParseCertificate(block.Bytes)
		if err != nil {
			fmt.Fprintf(os.Stderr, "certificate authority '%s': not a valid certificate (%s)\n", opt.CA, err)
			os.Exit(2)
		}
	}

	raw, err = ioutil.ReadFile(opt.Cert)
	if err != nil {
		fmt.Fprintf(os.Stderr, "certificate '%s': %s\n", opt.Cert, err)
		os.Exit(2)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		fmt.Fprintf(os.Stderr, "certificate '%s': not a valid PEM file\n", opt.Cert)
		os.Exit(2)
	}
	if block.Type != "CERTIFICATE" {
		fmt.Fprintf(os.Stderr, "certificate '%s': not a certificate\n", opt.Cert)
		os.Exit(2)
	}
	cert, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "certificate '%s': not a valid certificate (%s)\n", opt.Cert, err)
		os.Exit(2)
	}

	raw, err = ioutil.ReadFile(opt.Key)
	if err != nil {
		fmt.Fprintf(os.Stderr, "private key '%s': %s\n", opt.Key, err)
		os.Exit(2)
	}
	block, _ = pem.Decode(raw)
	if block == nil {
		fmt.Fprintf(os.Stderr, "private key '%s': not a valid PEM file\n", opt.Key)
		os.Exit(2)
	}
	key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "private key '%s': not a valid private key (%s)\n", opt.Key, err)
		os.Exit(2)
	}

	if cert.PublicKeyAlgorithm != x509.RSA {
		fmt.Printf("certificate '%s': not an RSA-derived certificate\n", opt.Cert)
		os.Exit(3)
	}
	pub := cert.PublicKey.(*rsa.PublicKey)
	if pub.N.Cmp(key.N) != 0 {
		fmt.Printf("certificate '%s' modulus doesn't match that of private key %s\n", opt.Cert, opt.Key)
		os.Exit(4)
	}
	if pub.E != key.E {
		fmt.Printf("certificate '%s' exponent doesn't match that of private key %s\n", opt.Cert, opt.Key)
		os.Exit(5)
	}

	if ca != nil {
		if err := cert.CheckSignatureFrom(ca); err != nil {
			fmt.Printf("certificate '%s' isn't signed by certificate authority '%s' (%s)\n", opt.Cert, opt.CA, err)
			os.Exit(6)
		}
	}

	fmt.Printf("x509 ok!\n")
	os.Exit(0)
}
