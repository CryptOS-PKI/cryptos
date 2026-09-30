package console

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
	"context"
	"fmt"

	cryptosv1 "github.com/CryptOS-PKI/api/go/cryptos/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// Client is an on-box gRPC client of the local node service. It dials the
// plaintext UNIX socket the node exposes on the loopback path and reads the
// status and identity used to render the console dashboard.
type Client struct {
	conn *grpc.ClientConn
	node cryptosv1.NodeServiceClient
}

// Dial connects to the node's local UNIX socket without TLS. It mirrors the
// socket dial in cmd/cryptosctl/client.go: the on-box socket is plaintext and
// authenticated by filesystem permissions, not mTLS.
func Dial(socketPath string) (*Client, error) {
	conn, err := grpc.NewClient("unix:"+socketPath, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", socketPath, err)
	}
	return &Client{conn: conn, node: cryptosv1.NewNodeServiceClient(conn)}, nil
}

// Snapshot fetches the current node status and identity and maps them into a
// dashboard View, stamped with the measured node uptime. When GetStatus fails
// it returns a degraded View and the error so the caller can render the
// degraded frame while the node is unreachable. A GetIdentity failure is
// non-fatal: the View is still returned with an empty Root CN.
func (c *Client) Snapshot(ctx context.Context) (View, error) {
	statusResp, err := c.node.GetStatus(ctx, &cryptosv1.GetStatusRequest{})
	if err != nil {
		return View{Degraded: true}, fmt.Errorf("get status: %w", err)
	}
	var id *cryptosv1.Identity
	if idResp, err := c.node.GetIdentity(ctx, &cryptosv1.GetIdentityRequest{}); err == nil {
		id = idResp.GetIdentity()
	}
	return ViewFromAPI(statusResp.GetStatus(), id, Uptime()), nil
}

// Reset asks the node to erase its key material and reboot into setup. It
// carries the operator-typed Root CA CN so the node can verify the caller named
// the correct CA before wiping. The node only honors Reset on this local
// socket; on the mTLS listener the same RPC returns Unimplemented.
func (c *Client) Reset(ctx context.Context, confirmCN string) error {
	_, err := c.node.Reset(ctx, &cryptosv1.ResetRequest{ConfirmCommonName: confirmCN})
	if err != nil {
		return fmt.Errorf("reset: %w", err)
	}
	return nil
}

// Close releases the underlying connection.
func (c *Client) Close() error {
	return c.conn.Close()
}
