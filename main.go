package main

import (
	"github.com/bwesterb/go-atum"   // imported as atum
	"github.com/bwesterb/go-xmssmt" // imported as xmssmt

	"golang.org/x/crypto/ed25519"
	"gopkg.in/yaml.v2"

	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/signal"
	"time"
)

// Configuration of the atum server
type Conf struct {
	// The maximum size of nonces to accept
	MaxNonceSize int `yaml:"maxNonceSize"`

	// Maximum lag in seconds to accept
	AcceptableLag int `yaml:"acceptableLag"`

	// Default signature algorithm the server uses
	DefaultSigAlg atum.SignatureAlgorithm `yaml:"defaultSigAlg"`

	// Path to store XMSSMT key
	XMSSMTKeyPath string `yaml:"xmssmtKeyPath"`

	// Path to store ED25519 key
	Ed25519KeyPath string `yaml:"ed25519KeyPath"`

	// Address to bind to
	BindAddr string `yaml:"bindAddr"`

	// XMSS[MT] algorithm to use when generating a new key
	XMSSMTAlg string `yaml:"xmssmtAlg"`
}

// Globals
var (
	// Configuration
	conf Conf

	ed25519Sk ed25519.PrivateKey
	ed25519Pk ed25519.PublicKey

	xmssmtSk *xmssmt.PrivateKey
	xmssmtPk *xmssmt.PublicKey

	serverInfo atum.ServerInfo
)

func serverInfoHandler(w http.ResponseWriter, r *http.Request) {
	buf, _ := json.Marshal(serverInfo)
	w.Write(buf)
}

func requestHandler(w http.ResponseWriter, r *http.Request) {
	var req atum.Request
	reqBytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return
	}
	if err = json.Unmarshal(reqBytes, &req); err != nil {
		http.Error(w, "Failed to parse JSON", http.StatusBadRequest)
		return
	}
	// TODO finish
}

func rootHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		serverInfoHandler(w, r)
	case "POST":
		requestHandler(w, r)
	default:
		http.Error(w,
			fmt.Sprintf("Don't know what to do with %s", r.Method),
			http.StatusBadRequest)
		return
	}
}

func main() {
	var confPath string

	// configuration default
	conf.MaxNonceSize = 128
	conf.AcceptableLag = 60
	conf.DefaultSigAlg = "xmssmt"
	conf.XMSSMTKeyPath = "xmssmt.key"
	conf.Ed25519KeyPath = "ed25519.key"
	conf.BindAddr = ":8080"
	conf.XMSSMTAlg = "XMSSMT-SHAKE_40/4_512"

	// parse commandline
	flag.StringVar(&confPath, "config", "config.yaml",
		"path to configuration file")
	flag.Parse()

	// parse configuration file
	if _, err := os.Stat(confPath); os.IsNotExist(err) {
		fmt.Printf("Error: could not find configuration file: %s\n\n", confPath)
		fmt.Printf("Example configuration file:\n\n")

		buf, _ := yaml.Marshal(&conf)
		fmt.Printf("%s\n", buf) // TODO indent
		return
	}

	// load keys
	loadEd25519Key()
	loadXMSSMTKey()

	log.Printf("Ed25519 public key: %s",
		base64.RawURLEncoding.EncodeToString(ed25519Pk))
	xmssmtPkText, _ := xmssmtPk.MarshalText()
	log.Printf("XMSSMT public key:  %s", xmssmtPkText)

	// set up server information struct
	serverInfo = atum.ServerInfo{
		MaxNonceSize:  conf.MaxNonceSize,
		AcceptableLag: conf.AcceptableLag,
		DefaultSigAlg: conf.DefaultSigAlg,
	}

	// set up HTTP server
	http.HandleFunc("/", rootHandler)

	// set up signal handler to catch keyboard interrupt
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt)
	go func() {
		<-signalChan
		log.Printf("SIGINT received, closing XMSS[MT] private key container")
		if err := xmssmtSk.Close(); err != nil {
			log.Printf("  ... failed: %v", err)
			os.Exit(1)
		} else {
			log.Printf("  ... done!")
		}
		os.Exit(0)
	}()

	// Run HTTP server
	log.Printf("Listening on %s", conf.BindAddr)
	log.Fatal(http.ListenAndServe(conf.BindAddr, nil))
}

func loadXMSSMTKey() {
	fileInfo, err := os.Stat(conf.XMSSMTKeyPath)

	if os.IsNotExist(err) {
		log.Printf("%s does not exist. Generating key ...", conf.XMSSMTKeyPath)

		xmssmtSk, xmssmtPk, err = xmssmt.GenerateKeyPair(
			conf.XMSSMTAlg, conf.XMSSMTKeyPath)
		if err != nil {
			log.Fatalf("xmssmt.GenerateKeyPair: %v", err)
		}
		return
	}

	if err != nil {
		log.Fatalf("os.Stat(%s): %v", conf.XMSSMTKeyPath, err)
	}

	// This check is not perfect (ie. symlinks), but it helps a bit.
	if fileInfo.Mode().Perm()&077 != 0 {
		log.Fatalf("I don't trust the permission %#o on %s",
			fileInfo.Mode().Perm(), conf.XMSSMTKeyPath)
	}

	var lostSigs uint32
	xmssmtSk, xmssmtPk, lostSigs, err = xmssmt.LoadPrivateKey(conf.XMSSMTKeyPath)
	if err != nil {
		log.Fatalf("xmssmt.LoadPrivateKey(%s): %v",
			conf.XMSSMTKeyPath, err)
	}

	if lostSigs != 0 {
		log.Printf("WARNING Lost %d XMSS[MT] signatures.", lostSigs)
		log.Printf("        This might have been caused by a crash")
	}

	// TODO check if Params() are the same as in settings
}

func loadEd25519Key() {
	fileInfo, err := os.Stat(conf.Ed25519KeyPath)
	if os.IsNotExist(err) {
		log.Printf("%s does not exist. Generating key ...", conf.Ed25519KeyPath)
		ed25519Pk, ed25519Sk, err = ed25519.GenerateKey(nil)
		if err != nil {
			log.Fatalf("ed25519.GenerateKey: %v", err)
		}
		err = ioutil.WriteFile(conf.Ed25519KeyPath, []byte(ed25519Sk), 0600)
		if err != nil {
			log.Fatalf("ioutil.WriteFile(%s):%v", conf.Ed25519KeyPath, err)
		}
		return
	}

	if err != nil {
		log.Fatalf("os.Stat(%s): %v", conf.Ed25519KeyPath, err)
	}

	// This check is not perfect (ie. symlinks), but it helps a bit.
	if fileInfo.Mode().Perm()&077 != 0 {
		log.Fatalf("I don't trust the permission %#o on %s",
			fileInfo.Mode().Perm(), conf.Ed25519KeyPath)
	}

	buf, err := ioutil.ReadFile(conf.Ed25519KeyPath)
	if err != nil {
		log.Fatalf("Couldn't read %s: %v", conf.Ed25519KeyPath, err)
	}

	ed25519Sk = ed25519.PrivateKey(buf)
	var ok bool
	ed25519Pk, ok = ed25519Sk.Public().(ed25519.PublicKey)
	if !ok {
		log.Fatalf("Couldn't derive ed25519 public key from %s",
			conf.Ed25519KeyPath)
	}
}
