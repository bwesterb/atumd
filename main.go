package main

import (
	"github.com/bwesterb/go-atum" // imported as atum
	"github.com/bwesterb/go-atum/stamper"
	"github.com/bwesterb/go-pow"    // imported as pow
	"github.com/bwesterb/go-xmssmt" // imported as xmssmt

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/sha3"
	"gopkg.in/yaml.v2"

	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"time"
)

// Configuration of the atum server
type Conf struct {
	// Canonical URL
	CanonicalUrl string `yaml:"canonicalUrl"`

	// The maximum size of nonces to accept
	MaxNonceSize int64 `yaml:"maxNonceSize"`

	// Maximum lag in seconds to accept
	AcceptableLag int64 `yaml:"acceptableLag"`

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

	// Proof of Work difficulty for XMSSMT.
	XMSSMTPowDifficulty *uint32 `yaml:"xmssmtPowDifficulty"`

	// Number of signature sequence numbers to preallocate.  If the server
	// crashes, this is the amount of signatures lost.
	XMSSMTBorrowedSeqNos *uint32 `taml:"xmssmtBorrowedSeqNos"`

	// Proof of Work difficulty for Ed25519.
	Ed25519PowDifficulty *uint32 `yaml:"ed25519PowDifficulty"`

	// Key to generate Proof of Work nonces with
	PowKey []byte `yaml:"powKey"`

	// Interval between changing the proof of work nonces
	PowWindow time.Duration `yaml:"powWindow"`

	// List of other public keys that we should tell clients to trust
	// for this server Url.  The might be old public keys, or public keys
	// of others servers behind the same Url.
	OtherTrustedPublicKeys []AlgPkPair `yaml:"otherTrustedPublicKeys"`

	// How often should clients check in about public keys
	PublicKeyCacheDuration time.Duration `yaml:"publicKeyCacheDuration"`

	// Enable prometheus metrics.
	//
	// NOTE, these are publicly exposed at /metrics.
	EnableMetrics bool `yaml:"enableMetrics"`
}

type AlgPkPair struct {
	Alg       atum.SignatureAlgorithm
	PublicKey []byte
}

func (pair *AlgPkPair) UnmarshalText(buf []byte) error {
	var err error
	bits := strings.SplitN(string(buf), "-", 2)
	if len(bits) != 2 {
		return fmt.Errorf("Should have one a dash between alg type and pk")
	}
	pair.Alg = atum.SignatureAlgorithm(bits[0])
	pair.PublicKey, err = base64.StdEncoding.DecodeString(bits[1])
	if err != nil {
		return err
	}
	return nil
}

func (pair AlgPkPair) String() string {
	return fmt.Sprintf("%s-%s",
		pair.Alg,
		base64.StdEncoding.EncodeToString(pair.PublicKey))
}

// Globals
var (
	// Configuration
	conf Conf

	// Keypairs
	ed25519Sk ed25519.PrivateKey
	ed25519Pk ed25519.PublicKey

	xmssmtSk *xmssmt.PrivateKey
	xmssmtPk *xmssmt.PublicKey

	// Other trusted public keys
	trustedPkLut map[string]bool

	// Server info (and lock)
	serverInfo     atum.ServerInfo
	serverInfoLock sync.Mutex

	// Prometheus metrics
	metrStampDuration = prometheus.NewSummaryVec(
		prometheus.SummaryOpts{
			Name:       "atumd_stamp_duration_seconds",
			Help:       "Time it took to set timestamp",
			Objectives: map[float64]float64{0.5: 0.05, 0.9: 0.01, 0.99: 0.001},
		}, []string{"alg"},
	)

	metrStampErrors = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "atumd_stamp_errors",
			Help: "Errors by clients that requested timestamps",
		}, []string{"code"},
	)

	metrPkChecks = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "atumd_pkchecks",
			Help: "Number of times a public key was checked",
		})

	metrXmssmtSkUsed = prometheus.NewCounterFunc(
		prometheus.CounterOpts{
			Name: "atumd_xmssmt_skused",
			Help: "Fraction of signatures used",
		}, func() float64 {
			params := xmssmtSk.Context().Params()
			return float64(xmssmtSk.SeqNo()) / float64(params.MaxSignatureSeqNo())
		})
	metrXmssmtUnretiredSeqnos = prometheus.NewCounterFunc(
		prometheus.CounterOpts{
			Name: "atumd_xmssmt_unretired_seqnos",
			Help: "Number of unretired signature seqnos",
		}, func() float64 {
			return float64(xmssmtSk.UnretiredSeqNos())
		})
	metrXmssmtCachedSubtrees = prometheus.NewCounterFunc(
		prometheus.CounterOpts{
			Name: "atumd_xmssmt_cached_subtrees",
			Help: "Number of subtrees in cache",
		}, func() float64 {
			return float64(xmssmtSk.CachedSubTrees())
		})
	metrXmssmtBorrowedSeqNos = prometheus.NewCounterFunc(
		prometheus.CounterOpts{
			Name: "atumd_xmssmt_borrowed_seqnos",
			Help: "Number of signature seqnos borrowed from privkey container",
		}, func() float64 {
			return float64(xmssmtSk.BorrowedSeqNos())
		})
)

func registerMetrics() {
	prometheus.MustRegister(metrStampDuration)
	prometheus.MustRegister(metrStampErrors)
	prometheus.MustRegister(metrPkChecks)
	prometheus.MustRegister(metrXmssmtSkUsed)
	prometheus.MustRegister(metrXmssmtUnretiredSeqnos)
	prometheus.MustRegister(metrXmssmtCachedSubtrees)
	prometheus.MustRegister(metrXmssmtBorrowedSeqNos)
}

// Recompute proof of work nonces
func computePowNonces() {
	now := time.Now()
	nonce := make([]byte, 32)
	startOfWindow := now.Truncate(conf.PowWindow)
	h := sha3.NewShake128()
	h.Write(conf.PowKey)
	buf, _ := startOfWindow.MarshalBinary()
	h.Write(buf)
	h.Read(nonce)
	log.Printf("Proof of work nonce: %s",
		base64.StdEncoding.EncodeToString(nonce))
	serverInfoLock.Lock()
	defer serverInfoLock.Unlock()

	if conf.Ed25519PowDifficulty != nil {
		serverInfo.RequiredProofOfWork[atum.Ed25519] = pow.Request{
			Difficulty: *conf.Ed25519PowDifficulty,
			Nonce:      nonce,
			Alg:        pow.Sha2BDay,
		}
	}
	if conf.XMSSMTPowDifficulty != nil {
		serverInfo.RequiredProofOfWork[atum.XMSSMT] = pow.Request{
			Difficulty: *conf.XMSSMTPowDifficulty,
			Nonce:      nonce,
			Alg:        pow.Sha2BDay,
		}
	}
}

func powNonceRevolver() {
	for {
		now := time.Now()
		startOfWindow := now.Truncate(conf.PowWindow)
		endOfWindow := startOfWindow.Add(conf.PowWindow)
		time.Sleep(endOfWindow.Sub(now))
		computePowNonces()
	}
}

func getServerInfo() *atum.ServerInfo {
	serverInfoLock.Lock()
	defer serverInfoLock.Unlock()
	info := serverInfo // this is a copy
	return &info
}

func serverInfoHandler(w http.ResponseWriter, r *http.Request) {
	info := getServerInfo()
	buf, _ := json.Marshal(info)
	w.Header().Set("Content-Type", "application/json")
	w.Write(buf)
}

func processAtumRequest(req atum.Request) (resp atum.Response) {
	var tsTime int64
	if req.Time != nil {
		lag := time.Now().Unix() - *req.Time
		if lag < 0 {
			lag = -lag
		}
		if lag > conf.AcceptableLag {
			resp.SetError(atum.ErrorCodeLag)
			resp.Info = getServerInfo()
			return
		}
		tsTime = *req.Time
	} else {
		tsTime = time.Now().Unix()
	}

	if req.Nonce == nil {
		resp.SetError(atum.ErrorMissingNonce)
		return
	}

	info := getServerInfo()
	if int64(len(req.Nonce)) > conf.MaxNonceSize {
		resp.SetError(atum.ErrorNonceTooLong)
		resp.Info = info
		return
	}

	alg := conf.DefaultSigAlg
	if req.PreferredSigAlg != nil {
		alg = *req.PreferredSigAlg
	}

	for {
		powReq, ok := info.RequiredProofOfWork[alg]
		if ok {
			if req.ProofOfWork == nil {
				resp.SetError(atum.ErrorMissingPow)
				resp.Info = info
				return
			}
			ok := req.ProofOfWork.Check(
				powReq,
				atum.EncodeTimeNonce(tsTime, req.Nonce))
			if !ok {
				resp.SetError(atum.ErrorPowInvalid)
				resp.Info = info
				return
			}
		}

		start := time.Now()
		switch alg {
		case atum.Ed25519:
			ts := stamper.CreateEd25519Timestamp(
				ed25519Sk, ed25519Pk, tsTime, req.Nonce)
			resp.Stamp = &ts
		case atum.XMSSMT:
			ts, err := stamper.CreateXMSSMTTimestamp(
				xmssmtSk, xmssmtPk, tsTime, req.Nonce)
			if err != nil {
				log.Printf("CreateXMSSMTTimestamp: %v", err)
			}
			resp.Stamp = ts
		default:
			alg = conf.DefaultSigAlg
			continue
		}
		metrStampDuration.With(prometheus.Labels{"alg": string(alg)}).Observe(
			time.Since(start).Seconds())

		// Check if we need to borrow new XMSSMT seqnos
		if alg == atum.XMSSMT && conf.XMSSMTBorrowedSeqNos != nil {
			if err := xmssmtSk.BorrowExactlyIfBelow(
				*conf.XMSSMTBorrowedSeqNos,
				*conf.XMSSMTBorrowedSeqNos/10); err != nil {
				log.Printf("BorrowExactlyIfBelow: %v", err)
			}
		}

		resp.Stamp.ServerUrl = conf.CanonicalUrl
		return
	}
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

	resp := processAtumRequest(req)
	if resp.Error != nil {
		metrStampErrors.With(prometheus.Labels{
			"code": string(*resp.Error)}).Inc()
	}

	w.Header().Set("Content-Type", "application/json")
	buf, _ := json.Marshal(resp)
	w.Write(buf)
}

func checkPkHandler(w http.ResponseWriter, r *http.Request) {
	hexPks, ok := r.URL.Query()["pk"]
	if !ok {
		http.Error(w, "Missing pk query parameter", http.StatusBadRequest)
		return
	}
	if len(hexPks) != 1 {
		http.Error(w, "Should only have only pk query parameter",
			http.StatusBadRequest)
		return
	}
	pk, err := hex.DecodeString(hexPks[0])
	if err != nil {
		http.Error(w, "Failed to parse pk parameter", http.StatusBadRequest)
		return
	}
	algs, ok := r.URL.Query()["alg"]
	if !ok {
		http.Error(w, "Missing alg query parameter", http.StatusBadRequest)
		return
	}
	if len(algs) != 1 {
		http.Error(w, "Should only have only alg query parameter",
			http.StatusBadRequest)
		return
	}
	alg := atum.SignatureAlgorithm(algs[0])
	_, ok = trustedPkLut[AlgPkPair{alg, pk}.String()]
	metrPkChecks.Inc()
	resp := atum.PublicKeyCheckResponse{
		Trusted: ok,
		Expires: time.Now().Add(conf.PublicKeyCacheDuration),
	}
	buf, _ := json.Marshal(resp)
	w.Header().Set("Content-Type", "application/json")
	w.Write(buf)
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
	var thousand uint32 = 1000
	conf.XMSSMTBorrowedSeqNos = &thousand
	conf.Ed25519PowDifficulty = nil
	var sixteen uint32 = 16
	conf.XMSSMTPowDifficulty = &sixteen
	conf.PowWindow, _ = time.ParseDuration("24h")
	conf.PublicKeyCacheDuration, _ = time.ParseDuration("720h")

	// parse commandline
	flag.StringVar(&confPath, "config", "config.yaml",
		"path to configuration file")
	flag.Parse()

	// Set up XMSSMT logging
	xmssmt.EnableLogging()

	// parse configuration file
	if _, err := os.Stat(confPath); os.IsNotExist(err) {
		fmt.Printf("Error: could not find configuration file: %s\n\n", confPath)
		fmt.Printf("Example configuration file:\n\n")

		buf, _ := yaml.Marshal(&conf)
		fmt.Printf("%s\n", buf) // TODO indent
		return
	} else {
		buf, err := ioutil.ReadFile(confPath)
		if err != nil {
			log.Fatalf("Could not read %s: %v", confPath, err)
		}
		err = yaml.Unmarshal(buf, &conf)
		if err != nil {
			log.Fatalf("Could not parse config files: %v", err)
		}
	}

	if conf.PowKey == nil {
		log.Printf("powKey is not set.  Generating a new one (again?) ...")
		conf.PowKey = make([]byte, 32)
		rand.Read(conf.PowKey)
	}

	if conf.CanonicalUrl == "" {
		conf.CanonicalUrl = fmt.Sprintf("https://%s", conf.BindAddr)
		log.Printf("canonicalUrl is not set.  Guessing %s", conf.CanonicalUrl)
	}

	// load keys
	loadEd25519Key()
	loadXMSSMTKey()

	log.Printf("Ed25519 public key: %s",
		base64.StdEncoding.EncodeToString(ed25519Pk))
	xmssmtPkText, _ := xmssmtPk.MarshalText()
	log.Printf("XMSSMT public key:  %s", xmssmtPkText)
	if conf.XMSSMTBorrowedSeqNos != nil {
		xmssmtSk.BorrowExactly(*conf.XMSSMTBorrowedSeqNos)
	}

	// set up server information struct
	serverInfo = atum.ServerInfo{
		MaxNonceSize:        conf.MaxNonceSize,
		AcceptableLag:       conf.AcceptableLag,
		DefaultSigAlg:       conf.DefaultSigAlg,
		RequiredProofOfWork: make(map[atum.SignatureAlgorithm]pow.Request),
	}
	computePowNonces()
	go powNonceRevolver()

	// Build the look-up-table of trusted public keys
	trustedPkLut = make(map[string]bool)
	xmssmtPkBytes, _ := xmssmtPk.MarshalBinary()
	trustedPkLut[AlgPkPair{atum.XMSSMT, xmssmtPkBytes}.String()] = true
	trustedPkLut[AlgPkPair{atum.Ed25519, []byte(ed25519Pk)}.String()] = true
	for _, pair := range conf.OtherTrustedPublicKeys {
		trustedPkLut[pair.String()] = true
	}

	// set up HTTP server
	http.HandleFunc("/checkPublicKey", checkPkHandler)
	http.HandleFunc("/", rootHandler)

	if conf.EnableMetrics {
		registerMetrics()
		http.Handle("/metrics", promhttp.Handler())
	}

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
