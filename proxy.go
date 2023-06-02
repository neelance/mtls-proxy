package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"

	kms "cloud.google.com/go/kms/apiv1"
	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	secretmanagerpb "cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"github.com/sethvargo/go-gcpkms/pkg/gcpkms"
)

func main() {
	ctx := context.Background()

	smClient, err := secretmanager.NewClient(ctx)
	if err != nil {
		log.Fatal(err)
	}
	defer smClient.Close()

	kmsClient, err := kms.NewKeyManagementClient(ctx)
	if err != nil {
		log.Fatal(err)
	}
	defer kmsClient.Close()

	targetHost := getenv("TARGET_HOST")

	rootCAs := x509.NewCertPool()
	rootCAs.AppendCertsFromPEM(accessSecret(ctx, smClient, getenv("ROOT_CA_SECRET")))

	block, _ := pem.Decode(accessSecret(ctx, smClient, getenv("CLIENT_CERT_SECRET")))

	signer, err := gcpkms.NewSigner(ctx, kmsClient, getenv("CLIENT_KEY_KMS_VERSION"))
	if err != nil {
		log.Fatal(err)
	}

	server := &http.Server{
		Addr: ":" + getenv("PORT"),
		Handler: &httputil.ReverseProxy{
			Rewrite: func(r *httputil.ProxyRequest) {
				r.SetURL(&url.URL{
					Scheme: "https",
					Host:   targetHost,
				})
			},
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs: rootCAs,
					Certificates: []tls.Certificate{{
						Certificate: [][]byte{block.Bytes},
						PrivateKey:  signer,
					}},
				},
			},
		},
	}

	log.Printf("listening on %s", server.Addr)
	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

func accessSecret(ctx context.Context, client *secretmanager.Client, name string) []byte {
	resp, err := client.AccessSecretVersion(ctx, &secretmanagerpb.AccessSecretVersionRequest{
		Name: name,
	})
	if err != nil {
		log.Fatal(err)
	}
	return resp.Payload.Data
}

func getenv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		log.Fatalf("missing required environment variable %q", key)
	}
	return v
}
