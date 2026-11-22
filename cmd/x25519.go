package cmd

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"github.com/spf13/cobra"
)

func init() {
	command.AddCommand(&cobra.Command{
		Use:   "x25519",
		Short: "Generate a new X25519 key pair",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			key, err := ecdh.X25519().GenerateKey(rand.Reader)
			if err != nil {
				return err
			}
			encode := base64.RawURLEncoding.EncodeToString
			fmt.Fprintf(cmd.OutOrStdout(), "Private key: %s\nPublic key: %s\n", encode(key.Bytes()), encode(key.PublicKey().Bytes()))
			return nil
		},
	})
}
