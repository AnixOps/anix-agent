package cmd

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	agentapi "github.com/AnixOps/anix-agent/v4/api/agent"
	"github.com/AnixOps/anix-agent/v4/api/agent/pki"
	"github.com/AnixOps/anix-agent/v4/conf"
	agentcontrol "github.com/AnixOps/anix-control/sdk/agentcontrol"
	"github.com/spf13/cobra"
)

// Exit statuses of `anix-agent join` (its help lists them; Control's
// installer reads them).
const (
	joinExitFailed      = 1
	joinExitUsage       = 2
	joinExitRejected    = 3
	joinExitUnreachable = 4
)

// joinFingerprintLabel starts the hashed input of the machine fingerprint
// (JoinRequest.machine_fingerprint).
const joinFingerprintLabel = "anixops-join-v1\n"

var (
	// joinRootCAs verifies Control's TLS certificate; nil uses the system
	// roots. Tests point it at their in-process Control's CA.
	joinRootCAs *x509.CertPool
	// machineIDFiles hold the machine ID, read in order.
	machineIDFiles = []string{"/etc/machine-id", "/var/lib/dbus/machine-id"}
	// joinDialTimeout bounds reaching Control; 0 uses the Agent's default.
	joinDialTimeout time.Duration
)

const joinLong = `Join this machine to AnixOps Control as a node. Control's installer runs it
as the Agent's user (anixops-agent) after installing the Agent and before
starting its service.

The token file holds one credential and must be private to the user (mode
0600 or stricter):
  anixjoin_...  a node group's join token: Control creates a node of the
                group, or gives this machine its earlier node of the group
                back (see --reset), and issues the node's certificate
  anixagt_...   a one-time enrollment credential of an existing node:
                Control issues that node's certificate

The certificate must name the node Control answered. It is stored in
<pki-dir>/<node> (identity.pem, ca.pem, identity.json, mode 0600), where
"anix-agent server" with AgentNode <node> and AgentIdentity.CertDir <pki-dir>
finds it and does not enroll again. The token file is removed once the
identity is stored.

A machine that already holds a usable identity under --pki-dir is left as it
is: join prints that node without contacting Control. --reset ignores the
identities on the machine (it does not remove them) and asks Control for a
new node, which gets a directory of its own.

Control is reached over TLS only, verified against the system roots for the
host of --grpc. A join sends the hex SHA-256 of "anixops-join-v1\n" and the
machine ID (/etc/machine-id, else /var/lib/dbus/machine-id; nothing without
one). It only selects the node a reinstalled machine may rejoin, and is
never authentication.

Output: one line, or with --json one JSON object on stdout:
  {"node":"proxy-12","node_name":"hk-01","group":"HK","created":true,
   "approval":"approved","spiffe_id":"spiffe://anixops/<cluster>/agent/proxy-12",
   "not_after":"2026-10-19T08:00:00Z"}
created is false when the machine rejoined its earlier node, for an
enrollment credential (its node existed) and for an identity already on the
machine. approval is "approved", "pending" (the group requires approval: the
node connects, and gets its configuration once an administrator approves
it), or "unknown" when Control did not say (an enrollment credential, an
identity already on the machine). node_name and group are empty when Control
did not name them. Errors go to stderr, with Control's error code.

Exit status:
  0  joined, or the machine already holds an identity
  1  any other failure: Control refused the request for another reason, the
     certificate is not the named node's, the identity could not be stored
  2  bad arguments: a flag, or a token file that is missing, not private, or
     holds no join token or enrollment credential
  3  Control rejected the token (join_rejected, agent_enrollment_rejected)
  4  Control could not be reached: network, TLS, or no answer in time`

// joinOptions are the flags of one join.
type joinOptions struct {
	control   string
	target    string
	tokenFile string
	name      string
	host      string
	addresses []string
	reset     bool
	pkiDir    string
	cluster   string
	json      bool
}

// joinOutput is the JSON object join prints with --json.
type joinOutput struct {
	Node     string `json:"node"`
	NodeName string `json:"node_name"`
	Group    string `json:"group"`
	Created  bool   `json:"created"`
	Approval string `json:"approval"`
	SPIFFEID string `json:"spiffe_id"`
	NotAfter string `json:"not_after"`
}

func init() {
	command.AddCommand(newJoinCommand())
}

func newJoinCommand() *cobra.Command {
	options := &joinOptions{}
	join := &cobra.Command{
		Use:   "join --control <https url> --grpc <host:port> --token-file <file>",
		Short: "Join this machine to Control as a node (exchange a join token for the node's identity)",
		Long:  joinLong,
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				return joinFail(cmd, joinExitUsage, fmt.Errorf("unexpected arguments %q", args))
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runJoin(cmd, options)
		},
		// Every error is printed by joinFail, and the usage is in --help.
		SilenceErrors: true,
		SilenceUsage:  true,
	}
	flags := join.Flags()
	flags.StringVar(&options.control, "control", "", "Control's URL (https://...)")
	flags.StringVar(&options.target, "grpc", "", "Control's agent listener, host:port")
	flags.StringVar(&options.tokenFile, "token-file", "", "file holding the anixjoin_ join token or the anixagt_ enrollment credential (mode 0600)")
	flags.StringVar(&options.name, "name", "", "name of a new node (default: Control uses the host name)")
	flags.StringVar(&options.host, "host", "", "address clients connect to (default: Control uses the first --address)")
	flags.StringArrayVar(&options.addresses, "address", nil, "this machine's public address as Control sees it; repeat for each, IPv4 first (empty values are skipped)")
	flags.BoolVar(&options.reset, "reset", false, "ignore identities already on this machine and ask Control for a new node, never the machine's earlier one")
	flags.StringVar(&options.pkiDir, "pki-dir", conf.DefaultAgentIdentityCertDir, "identity root (AgentIdentity.CertDir)")
	flags.StringVar(&options.cluster, "cluster", "", "accept only a certificate of this SPIFFE cluster (AgentIdentity.Cluster; default: Control's)")
	flags.BoolVar(&options.json, "json", false, "print one JSON object")
	join.SetFlagErrorFunc(func(cmd *cobra.Command, err error) error {
		return joinFail(cmd, joinExitUsage, err)
	})
	return join
}

// runJoin joins, or reports the identity the machine already holds.
func runJoin(cmd *cobra.Command, options *joinOptions) error {
	config, err := options.joinConfig()
	if err != nil {
		return joinFail(cmd, joinExitUsage, err)
	}
	if !options.reset {
		identity, store, err := pki.Newest(options.pkiDir, options.cluster, time.Now())
		switch {
		case err == nil:
			return printJoin(cmd.OutOrStdout(), options.json, existingJoinOutput(identity),
				fmt.Sprintf("This machine already holds the identity of %s in %s (%s, valid until %s); Control was not contacted. Use --reset to join as a new node.",
					identity.Node, store.Dir(), identity.SPIFFEID, identity.NotAfter.UTC().Format(time.RFC3339)))
		case !errors.Is(err, pki.ErrNotEnrolled):
			return joinFail(cmd, joinExitFailed, fmt.Errorf("read the identities in %s: %w", options.pkiDir, err))
		}
	}
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	result, err := agentapi.Join(ctx, config)
	if err != nil {
		return joinFail(cmd, joinExitStatus(err), err)
	}
	if err := os.Remove(options.tokenFile); err != nil && !errors.Is(err, fs.ErrNotExist) {
		fmt.Fprintf(cmd.ErrOrStderr(), "anix-agent join: warning: could not remove the used token file: %v\n", err)
	}
	return printJoin(cmd.OutOrStdout(), options.json, joinResultOutput(result), joinSummary(result, options.control))
}

// joinConfig checks the flags and reads the token.
func (o *joinOptions) joinConfig() (agentapi.JoinConfig, error) {
	var config agentapi.JoinConfig
	control, err := url.Parse(strings.TrimSpace(o.control))
	if o.control == "" || err != nil || control.Scheme != "https" || control.Hostname() == "" {
		return config, fmt.Errorf("--control must be Control's https:// URL, not %q", o.control)
	}
	target := strings.TrimSpace(o.target)
	host, port, err := net.SplitHostPort(target)
	if number, portErr := strconv.Atoi(port); target == "" || err != nil || host == "" || portErr != nil || number < 1 || number > 65535 {
		return config, fmt.Errorf("--grpc must be Control's agent listener as host:port, not %q", o.target)
	}
	if o.tokenFile == "" {
		return config, errors.New("--token-file is required")
	}
	if !filepath.IsAbs(o.pkiDir) {
		return config, fmt.Errorf("--pki-dir %q must be an absolute path", o.pkiDir)
	}
	o.pkiDir = filepath.Clean(o.pkiDir)
	o.cluster = strings.TrimSpace(o.cluster)
	if err := (conf.AgentIdentityConfig{Cluster: o.cluster}).Validate(); err != nil {
		return config, fmt.Errorf("--cluster: %w", err)
	}
	addresses := make([]string, 0, len(o.addresses))
	for _, address := range o.addresses {
		// An empty value is an address the installer did not find.
		if address = strings.TrimSpace(address); address == "" {
			continue
		}
		if net.ParseIP(address) == nil {
			return config, fmt.Errorf("--address %q is not an IP address", address)
		}
		addresses = append(addresses, address)
	}
	token, err := agentapi.ReadCredentialFile(o.tokenFile, agentcontrol.JoinTokenPrefix, agentcontrol.EnrollmentCredentialPrefix)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return config, fmt.Errorf("token file %s does not exist", o.tokenFile)
	case err != nil:
		return config, err
	case token == "":
		return config, fmt.Errorf("token file %s is empty", o.tokenFile)
	}
	hostname, _ := os.Hostname()
	return agentapi.JoinConfig{
		Target: target, RootCAs: joinRootCAs, Credential: token,
		MachineFingerprint: machineFingerprint(machineIDFiles), Hostname: hostname,
		RequestedName: strings.TrimSpace(o.name), ConnectHost: strings.TrimSpace(o.host), PublicAddresses: addresses,
		Arch: runtime.GOARCH, OS: runtime.GOOS, AgentVersion: version, InstanceID: agentapi.InstanceID(hostname, "join"),
		Reset: o.reset, Cluster: o.cluster, Dir: o.pkiDir, DialTimeout: joinDialTimeout,
	}, nil
}

// machineFingerprint is the lowercase hex SHA-256 of joinFingerprintLabel
// and the first machine ID of paths, "" without one: a machine without an
// ID never rejoins.
func machineFingerprint(paths []string) string {
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		id := strings.TrimSpace(string(raw))
		if id == "" {
			continue
		}
		digest := sha256.Sum256([]byte(joinFingerprintLabel + id))
		return hex.EncodeToString(digest[:])
	}
	return ""
}

func joinResultOutput(result *agentapi.JoinResult) joinOutput {
	return joinOutput{
		Node: result.Identity.Node.String(), NodeName: result.NodeName, Group: result.Group,
		Created: result.Created, Approval: result.Approval,
		SPIFFEID: result.Identity.SPIFFEID, NotAfter: result.Identity.NotAfter.UTC().Format(time.RFC3339),
	}
}

// existingJoinOutput describes an identity already on the machine: Control
// was not asked, so whether the node waits for approval is unknown.
func existingJoinOutput(identity *pki.Identity) joinOutput {
	return joinOutput{
		Node: identity.Node.String(), Approval: agentapi.JoinApprovalUnknown,
		SPIFFEID: identity.SPIFFEID, NotAfter: identity.NotAfter.UTC().Format(time.RFC3339),
	}
}

// joinSummary is the human line of a join.
func joinSummary(result *agentapi.JoinResult, control string) string {
	identity := result.Identity
	var line string
	switch {
	case result.Identity.Bootstrap == pki.BootstrapEnrollmentCredential:
		line = fmt.Sprintf("Enrolled %s with %s", identity.Node, control)
	case result.Created:
		line = fmt.Sprintf("Joined %s as the new node %s (%s)", control, orDash(result.NodeName), identity.Node)
	default:
		line = fmt.Sprintf("Rejoined %s as the node %s (%s)", control, orDash(result.NodeName), identity.Node)
	}
	if result.Group != "" {
		line += " of group " + result.Group
	}
	line += fmt.Sprintf("; identity %s in %s, valid until %s.", identity.SPIFFEID, result.Dir, identity.NotAfter.UTC().Format(time.RFC3339))
	if result.Approval == agentapi.JoinApprovalPending {
		line += " The node waits for an administrator's approval before it gets its configuration and users."
	}
	return line
}

func printJoin(out io.Writer, asJSON bool, output joinOutput, line string) error {
	if !asJSON {
		_, err := fmt.Fprintln(out, line)
		return err
	}
	encoded, err := json.Marshal(output)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(out, string(encoded))
	return err
}

// joinExitStatus maps a failed join to its exit status.
func joinExitStatus(err error) int {
	switch {
	case errors.Is(err, agentapi.ErrJoinRejected):
		return joinExitRejected
	case errors.Is(err, agentapi.ErrJoinUnreachable):
		return joinExitUnreachable
	default:
		return joinExitFailed
	}
}

// joinFail prints err to stderr and ends join with status.
func joinFail(cmd *cobra.Command, status int, err error) error {
	fmt.Fprintf(cmd.ErrOrStderr(), "anix-agent join: %v\n", err)
	return &exitError{code: status, err: err}
}

// exitError ends the process with code; its message is printed already.
type exitError struct {
	code int
	err  error
}

func (e *exitError) Error() string { return e.err.Error() }
func (e *exitError) Unwrap() error { return e.err }

// ExitCode is the process's exit status for the error Run returned: 0
// without one, a command's own status, else 1.
func ExitCode(err error) int {
	if err == nil {
		return 0
	}
	var exit *exitError
	if errors.As(err, &exit) {
		return exit.code
	}
	return 1
}
