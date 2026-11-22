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
		Short: "Generate a random X25519 key pair",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			key, err := ecdh.X25519().GenerateKey(rand.Reader)
			if err != nil {
				return err
			}
			enc := base64.RawURLEncoding
			fmt.Fprintf(c.OutOrStdout(), "Private key: %s\nPublic key: %s\n",
				enc.EncodeToString(key.Bytes()), enc.EncodeToString(key.PublicKey().Bytes()))
			return nil
		},
	})
}
