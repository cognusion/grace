package gracehttp_test

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cognusion/grace/gracehttp"
)

const preStartProcessEnv = "GRACEHTTP_PRE_START_PROCESS"

func TestMain(m *testing.M) {
	const (
		testbinKey   = "GRACEHTTP_TEST_BIN"
		testbinValue = "1"
	)
	if os.Getenv(testbinKey) == testbinValue {
		testbinMain()
		return
	}
	if err := os.Setenv(testbinKey, testbinValue); err != nil {
		panic(err)
	}
	os.Exit(m.Run())
}

type response struct {
	Sleep time.Duration
	Pid   int
	Error string `json:",omitempty"`
}

// Wait for 10 consecutive responses from our own pid.
//
// This prevents flaky tests that arise from the fact that we have the
// perfectly acceptable (read: not a bug) condition where both the new and the
// old servers are accepting requests. In fact the amount of time both are
// accepting at the same time and the number of requests that flip flop between
// them is unbounded and in the hands of the various kernels our code tends to
// run on.
//
// In order to combat this, we wait for 10 successful responses from our own
// pid. This is a somewhat reliable way to ensure the old server isn't
// serving anymore.
func wait(wg *sync.WaitGroup, url string) {
	var success int
	defer wg.Done()
	for {
		res, err := http.Get(url)
		if err == nil {
			// ensure it isn't a response from a previous instance
			defer res.Body.Close()
			var r response
			if err := json.NewDecoder(res.Body).Decode(&r); err != nil {
				log.Fatalf("Error decoding json: %s", err)
			}
			if r.Pid == os.Getpid() {
				success++
				if success == 10 {
					return
				}
				continue
			}
		} else {
			success = 0
			// we expect connection refused
			if !strings.HasSuffix(err.Error(), "connection refused") {
				e2 := json.NewEncoder(os.Stderr).Encode(&response{
					Error: err.Error(),
					Pid:   os.Getpid(),
				})
				if e2 != nil {
					log.Fatalf("Error writing error json: %s", e2)
				}
			}
		}
	}
}

func httpsServer(addr string) *http.Server {
	cert, err := tls.X509KeyPair(localhostCert, localhostKey)
	if err != nil {
		log.Fatalf("error loading cert: %v", err)
	}
	return &http.Server{
		Addr:    addr,
		Handler: newHandler(),
		TLSConfig: &tls.Config{
			NextProtos:   []string{"http/1.1"},
			Certificates: []tls.Certificate{cert},
		},
	}
}

func testbinMain() {
	var httpAddr, httpsAddr string
	var testOption int
	flag.StringVar(&httpAddr, "http", ":48560", "http address to bind to")
	flag.StringVar(&httpsAddr, "https", ":48561", "https address to bind to")
	flag.IntVar(&testOption, "testOption", -1, "which option to test on ServeWithOptions")
	flag.Parse()

	// we have self signed certs
	http.DefaultTransport = &http.Transport{
		DisableKeepAlives: true,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}

	// print json to stderr once we can successfully connect to all three
	// addresses. the ensures we only print the line once we're ready to serve.
	go func() {
		var wg sync.WaitGroup
		wg.Add(2)
		go wait(&wg, fmt.Sprintf("http://%s/sleep/?duration=1ms", httpAddr))
		go wait(&wg, fmt.Sprintf("https://%s/sleep/?duration=1ms", httpsAddr))
		wg.Wait()

		err := json.NewEncoder(os.Stderr).Encode(&response{Pid: os.Getpid()})
		if err != nil {
			log.Fatalf("Error writing startup json: %s", err)
		}
	}()

	servers := []*http.Server{
		&http.Server{Addr: httpAddr, Handler: newHandler()},
		httpsServer(httpsAddr),
	}

	if testOption == -1 {
		err := gracehttp.Serve(servers...)
		if err != nil {
			log.Fatalf("Error in gracehttp.Serve: %s", err)
		}
	} else {
		if testOption == testPreStartProcess {
			switch os.Getenv(preStartProcessEnv) {
			case "":
				err := os.Setenv(preStartProcessEnv, "READY")
				if err != nil {
					log.Fatalf("testbin (first incarnation) could not set %v to 'ready': %v", preStartProcessEnv, err)
				}
			case "FIRED":
				// all good, reset for next round
				err := os.Setenv(preStartProcessEnv, "READY")
				if err != nil {
					log.Fatalf("testbin (second incarnation) could not reset %v to 'ready': %v", preStartProcessEnv, err)
				}
			case "READY":
				log.Fatalf("failure to update startup hook before new process started")
			default:
				log.Fatalf("something strange happened with %v: it ended up as %v, which is not '', 'FIRED', or 'READY'", preStartProcessEnv, os.Getenv(preStartProcessEnv))
			}

			err := gracehttp.ServeWithOptions(
				servers,
				gracehttp.PreStartProcess(func() error {
					err := os.Setenv(preStartProcessEnv, "FIRED")
					if err != nil {
						log.Fatalf("startup hook could not set %v to 'fired': %v", preStartProcessEnv, err)
					}
					return nil
				}),
			)
			if err != nil {
				log.Fatalf("Error in gracehttp.Serve: %s", err)
			}
		}
	}
}

func newHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/sleep/", func(w http.ResponseWriter, r *http.Request) {
		duration, err := time.ParseDuration(r.FormValue("duration"))
		if err != nil {
			http.Error(w, err.Error(), 400)
		}
		time.Sleep(duration)
		err = json.NewEncoder(w).Encode(&response{
			Sleep: duration,
			Pid:   os.Getpid(),
		})
		if err != nil {
			log.Fatalf("Error encoding json: %s", err)
		}
	})
	return mux
}

// localhostCert is a PEM-encoded TLS cert with SAN IPs
// "127.0.0.1" and "[::1]", expiring at the last second of 2049 (the end
// of ASN.1 time).
// generated from src/pkg/crypto/tls:
// go run generate_cert.go  --rsa-bits 1024 --host 127.0.0.1,::1,example.com --ca --start-date "Jan 1 00:00:00 1970" --duration=1000000h
var localhostCert = []byte(`-----BEGIN CERTIFICATE-----
MIICNTCCAZ6gAwIBAgIRAPCTVnGnhfjY10DlpUzojbowDQYJKoZIhvcNAQELBQAw
EjEQMA4GA1UEChMHQWNtZSBDbzAgFw03MDAxMDEwMDAwMDBaGA8yMDg0MDEyOTE2
MDAwMFowEjEQMA4GA1UEChMHQWNtZSBDbzCBnzANBgkqhkiG9w0BAQEFAAOBjQAw
gYkCgYEAttg5wF1WvTo3iU50pbed+UenJ4kllG48uQUd54/T8DngK4PXZbv0J3WN
4TXs1QAR/Po2n2SaCSuqeCNojvLaQV++KXLlVnqskFxrLC/gZJxJ36izrrY/RHNv
+T/oWUQ0AgcVtgszFsJeuTiEYIwgjq1PneCmNxTxye/iELU7q0sCAwEAAaOBiDCB
hTAOBgNVHQ8BAf8EBAMCAqQwEwYDVR0lBAwwCgYIKwYBBQUHAwEwDwYDVR0TAQH/
BAUwAwEB/zAdBgNVHQ4EFgQUG3kponrMnLYWi93G8Usdcr/vjnMwLgYDVR0RBCcw
JYILZXhhbXBsZS5jb22HBH8AAAGHEAAAAAAAAAAAAAAAAAAAAAEwDQYJKoZIhvcN
AQELBQADgYEAfZ9PNTeew9W/vg24R4W4pgWpLWHLgqAxjEauJ+lRw8b3BgHia3rw
oq/4f9JL4hQ5TrWF4WZb85+V3SisX+OwpbTXEdSklMDdV9gaRRWh01b9i4vX4Goj
aH6h5lSgkofABkX7fZrn6HFfaDW2U3Z1fr8AiEptzbGhfoXmuOBks9U=
-----END CERTIFICATE-----`)

// localhostKey is the private key for localhostCert.
var localhostKey = []byte(`-----BEGIN PRIVATE KEY-----
MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBALbYOcBdVr06N4lO
dKW3nflHpyeJJZRuPLkFHeeP0/A54CuD12W79Cd1jeE17NUAEfz6Np9kmgkrqngj
aI7y2kFfvily5VZ6rJBcaywv4GScSd+os662P0Rzb/k/6FlENAIHFbYLMxbCXrk4
hGCMII6tT53gpjcU8cnv4hC1O6tLAgMBAAECgYBwI5j308cY8xWQjp+X609lzX5F
DyYPLLTtPKgklt+DG9vSlF+Ms4OAl+ZWU35W/F4L62GIzGh0a2V3nS/JTERyfaWo
LUkKRTHeoOOZ5ZP8C/uspHcIYPT7ir/7s7hngXXjpVFHYrVo1oXK4EKtEIhz7fgU
hRlOla6jA0XZ9A8NcQJBAMis1oJiIOoI88nC5LtK5VIIe7Hbr6qUEddkgRDZuyNG
WEqYFrBR05I1lp70LbHFR3iSFxyI7ks3jk/Pr2E3iU8CQQDpQPQL55obNF6vjxPy
gIUPiLUx6bWy8DkRzMgkvQwMLoGabD455UcjLSoNJxmSl64J+mLzkLuaoGH0hUvt
tYdFAkEAlVynsJXvH6KYKYUJECo3sy4jOwdjoZfiC6p/shYNBr1V+/dlc8kDq2B9
gkQGOrm2b5R05UU57/wizV6sj7RxWwJAcEA88hm0FRF/27bcX6Cv6EjfAjU5pvJq
VIGbc+qyiI48+sbKr2wCbxBGI2xEp0JtlAm2Ywas8f3rBhS79JqejQJABvOjhVfl
8+VR9yjnWTKBHld6wOR5qEuSmakYpq66AK5OH3zFJMVVlHTALI5THX9gCfRhdPDR
D9c/LIEHyV+05g==
-----END PRIVATE KEY-----`)
