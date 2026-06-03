package main

/*
Apache License 2.0

Copyright 2026 Shane

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	cryptosv1 "github.com/CryptOS-PKI/api/go/cryptos/v1"
)

// dial connects to the node per the global flags and returns a client
// plus a closer. When --socket is set it dials the on-box UNIX socket
// without TLS; otherwise it dials the endpoint with mTLS TLS 1.3.
func dial(opts *globalOpts) (cryptosv1.NodeServiceClient, func() error, error) {
	var target string
	var creds credentials.TransportCredentials

	if opts.socket != "" {
		target = "unix:" + opts.socket
		creds = insecure.NewCredentials()
	} else {
		tlsCfg, err := clientTLSConfig(opts)
		if err != nil {
			return nil, nil, err
		}
		target = opts.endpoint
		creds = credentials.NewTLS(tlsCfg)
	}

	conn, err := grpc.NewClient(target, grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, nil, fmt.Errorf("dial %s: %w", target, err)
	}
	return cryptosv1.NewNodeServiceClient(conn), conn.Close, nil
}

// clientTLSConfig builds the mTLS client config from the identity, key,
// and trust files named in opts.
func clientTLSConfig(opts *globalOpts) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(opts.identityCert, opts.identityKey)
	if err != nil {
		return nil, fmt.Errorf("load client identity: %w", err)
	}
	trustPEM, err := os.ReadFile(opts.trustCert)
	if err != nil {
		return nil, fmt.Errorf("read trust cert: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(trustPEM) {
		return nil, fmt.Errorf("trust cert %s contains no PEM certificates", opts.trustCert)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		MinVersion:   tls.VersionTLS13,
		ServerName:   serverName(opts),
	}, nil
}

// serverName resolves the TLS server name: the explicit override, else
// the host portion of the endpoint.
func serverName(opts *globalOpts) string {
	if opts.serverName != "" {
		return opts.serverName
	}
	host := opts.endpoint
	if i := strings.LastIndex(host, ":"); i >= 0 {
		host = host[:i]
	}
	return host
}

// errNoIdentity is returned when GetIdentity reports the node has no
// identity yet (the ceremony has not run).
var errNoIdentity = errors.New("node has no identity yet (run 'cryptosctl ceremony start')")
