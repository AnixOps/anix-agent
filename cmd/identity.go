package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"text/tabwriter"
	"time"

	"github.com/AnixOps/anix-agent/v4/api/agent/pki"
	"github.com/AnixOps/anix-agent/v4/conf"
	agentcontrol "github.com/AnixOps/anix-control/sdk/agentcontrol"
	"github.com/spf13/cobra"
)

var (
	identityJSON   bool
	identityPKIDir string
)

var identityCommand = cobra.Command{
	Use:   "identity",
	Short: "Show the mTLS identity (certificate and expiry) of each node's Agent control stream",
	Long: `Show the mTLS identity of each node's Agent control stream: the SPIFFE ID
Control issued, the certificate serial, its expiry and renewal time, and
whether the stored key and certificate are usable. It reads the identity
directories (AgentIdentity.CertDir, default /var/lib/anix-agent/pki) and
never contacts Control.`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		roots, nodes := identityRoots()
		statuses, err := collectIdentityStatuses(roots, nodes, time.Now())
		if err != nil {
			return err
		}
		return printIdentityStatuses(cmd.OutOrStdout(), statuses, identityJSON, time.Now())
	},
}

func init() {
	identityCommand.Flags().BoolVar(&identityJSON, "json", false, "print JSON")
	identityCommand.Flags().StringVar(&identityPKIDir, "pki-dir", "", "identity root to read instead of the configured AgentIdentity.CertDir")
	command.AddCommand(&identityCommand)
}

// identityRoots returns the identity roots to read and the configured
// nodes: --pki-dir, else every AgentIdentity.CertDir of the configuration
// (the default root when it cannot be read).
func identityRoots() ([]string, map[string][]agentcontrol.AgentNode) {
	if identityPKIDir != "" {
		return []string{identityPKIDir}, nil
	}
	loaded := conf.New()
	if err := loaded.LoadFromPath(config); err != nil {
		fmt.Fprintf(os.Stderr, "cannot read %s (%v); showing %s\n", config, err, conf.DefaultAgentIdentityCertDir)
		return []string{conf.DefaultAgentIdentityCertDir}, nil
	}
	seen := map[string]bool{}
	nodes := map[string][]agentcontrol.AgentNode{}
	var roots []string
	for _, node := range loaded.NodeConfig {
		api := node.ApiConfig
		if !api.AgentControlEnabled {
			continue
		}
		root := api.AgentIdentity.Dir()
		if !seen[root] {
			seen[root] = true
			roots = append(roots, root)
		}
		if api.NodeID > 0 {
			nodes[root] = append(nodes[root], agentcontrol.AgentNode{Kind: agentcontrol.NodeKindProxy, ID: uint32(api.NodeID)}) // #nosec G115 -- node IDs are uint32 on the wire.
		}
	}
	if loaded.Forward.ForwardNodeOnly() {
		// A forward node's identity (forward-<id>).
		api := loaded.Forward.ForwardNode
		root := api.AgentIdentity.Dir()
		if !seen[root] {
			seen[root] = true
			roots = append(roots, root)
		}
		nodes[root] = append(nodes[root], agentcontrol.AgentNode{Kind: agentcontrol.NodeKindForward, ID: uint32(api.NodeID)}) // #nosec G115 -- node IDs are uint32 on the wire.
	}
	if len(roots) == 0 {
		roots = []string{conf.DefaultAgentIdentityCertDir}
	}
	return roots, nodes
}

// collectIdentityStatuses inspects every node directory under roots, and
// each configured node even before it has a directory.
func collectIdentityStatuses(roots []string, nodes map[string][]agentcontrol.AgentNode, now time.Time) ([]pki.Status, error) {
	var statuses []pki.Status
	seen := map[string]bool{}
	for _, root := range roots {
		stores, err := pki.List(root)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", root, err)
		}
		for _, node := range nodes[root] {
			store, err := pki.NewStore(root, node)
			if err == nil {
				stores = append(stores, store)
			}
		}
		for _, store := range stores {
			if seen[store.Dir()] {
				continue
			}
			seen[store.Dir()] = true
			statuses = append(statuses, store.Inspect(now))
		}
	}
	sort.Slice(statuses, func(i, j int) bool { return statuses[i].Dir < statuses[j].Dir })
	return statuses, nil
}

func printIdentityStatuses(out io.Writer, statuses []pki.Status, asJSON bool, now time.Time) error {
	if asJSON {
		encoder := json.NewEncoder(out)
		encoder.SetIndent("", "  ")
		if statuses == nil {
			statuses = []pki.Status{}
		}
		return encoder.Encode(statuses)
	}
	if len(statuses) == 0 {
		_, err := fmt.Fprintln(out, "No agent identity found.")
		return err
	}
	writer := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(writer, "NODE\tSTATE\tSPIFFE ID\tSERIAL\tEXPIRES (UTC)\tRENEWS (UTC)\tDIR")
	for _, status := range statuses {
		expires, renews := "-", "-"
		if !status.NotAfter.IsZero() {
			expires = status.NotAfter.UTC().Format("2006-01-02 15:04") + " (" + humanDuration(status.NotAfter.Sub(now)) + ")"
			renews = status.RenewAfter.UTC().Format("2006-01-02 15:04")
		}
		fmt.Fprintf(writer, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", status.Node, status.State, orDash(status.SPIFFEID), orDash(status.Serial), expires, renews, status.Dir)
	}
	if err := writer.Flush(); err != nil {
		return err
	}
	for _, status := range statuses {
		if status.Problem != "" {
			fmt.Fprintf(out, "%s: %s\n", status.Node, status.Problem)
		}
	}
	return nil
}

func orDash(value string) string {
	if value == "" {
		return "-"
	}
	return value
}

// humanDuration renders a duration as "6d 23h", "5h 10m" or "expired".
func humanDuration(d time.Duration) string {
	if d <= 0 {
		return "expired"
	}
	days := int(d / (24 * time.Hour))
	hours := int(d % (24 * time.Hour) / time.Hour)
	minutes := int(d % time.Hour / time.Minute)
	switch {
	case days > 0:
		return fmt.Sprintf("in %dd %dh", days, hours)
	case hours > 0:
		return fmt.Sprintf("in %dh %dm", hours, minutes)
	default:
		return fmt.Sprintf("in %dm", minutes)
	}
}
