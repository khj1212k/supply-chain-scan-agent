// h2probe: 표준 라이브러리 net/http 서버가 HTTP/2 를 말하는지 직접 확인한다 (127.0.0.1 만 쓴다).
//
//	plaintext: http.Serve (frontend 의 http.ListenAndServe 와 같은 평문 경로) 에 HTTP/2 연결 서문을 보낸다
//	tls:       http.ServeTLS (자체 서명 인증서) 에 ALPN h2 로 붙어 서문을 보낸다
//
// 서버가 HTTP/2 SETTINGS 프레임(type 0x4)으로 답하면 HTTP/2 를 말한 것이다.
// Rapid Reset(CVE-2023-44487) 은 HTTP/2 스트림을 열고 바로 취소하는 공격이라, HTTP/2 를 말하지 않는 서버에는 그 경로가 없다.
// 사용: GOTOOLCHAIN=go1.19.4 go run .   (frontend v0.5.0 Dockerfile 과 같은 툴체인)
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"runtime"
	"time"
)

const preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

// 빈 SETTINGS 프레임: 길이 0, type 4, flags 0, stream 0
var settings = []byte{0, 0, 0, 4, 0, 0, 0, 0, 0}

type result struct {
	Mode             string `json:"mode"`
	GoVersion        string `json:"go_version"`
	ALPN             string `json:"alpn,omitempty"`
	FirstBytes       string `json:"first_bytes"`
	ServerSpokeHTTP2 bool   `json:"server_spoke_http2"`
	HandlerSawProto  string `json:"handler_saw_proto,omitempty"`
	Err              string `json:"err,omitempty"`
}

func selfSigned() tls.Certificate {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "127.0.0.1"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}
}

func probe(mode string) result {
	r := result{Mode: mode, GoVersion: runtime.Version()}
	seen := make(chan string, 1)
	h := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		select {
		case seen <- req.Proto:
		default:
		}
		io.WriteString(w, "ok")
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		r.Err = err.Error()
		return r
	}
	srv := &http.Server{Handler: h}
	var c net.Conn
	if mode == "tls" {
		srv.TLSConfig = &tls.Config{Certificates: []tls.Certificate{selfSigned()}}
		go srv.ServeTLS(ln, "", "")
		tc, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2", "http/1.1"}})
		if err != nil {
			r.Err = err.Error()
			return r
		}
		r.ALPN = tc.ConnectionState().NegotiatedProtocol
		c = tc
	} else {
		go srv.Serve(ln)
		c, err = net.Dial("tcp", ln.Addr().String())
		if err != nil {
			r.Err = err.Error()
			return r
		}
	}
	defer c.Close()
	defer srv.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	c.Write(append([]byte(preface), settings...))
	buf := make([]byte, 64)
	n, _ := io.ReadAtLeast(c, buf, 9)
	r.FirstBytes = fmt.Sprintf("%q", buf[:n])
	r.ServerSpokeHTTP2 = n >= 9 && buf[3] == 0x4 && buf[5]|buf[6]|buf[7]|buf[8] == 0
	select {
	case p := <-seen:
		r.HandlerSawProto = p
	case <-time.After(200 * time.Millisecond):
	}
	return r
}

func main() {
	enc := json.NewEncoder(os.Stdout)
	for _, m := range []string{"plaintext", "tls"} {
		enc.Encode(probe(m))
	}
}
