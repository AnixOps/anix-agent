package anxline

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// Runner runs a host command; stdin may be empty.
type Runner interface {
	Run(ctx context.Context, stdin, name string, args ...string) (string, error)
}

// ExecRunner runs commands with os/exec.
type ExecRunner struct{}

// Run implements Runner.
func (ExecRunner) Run(ctx context.Context, stdin, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...) // #nosec G204 -- nft/ip with validated arguments.
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	if err != nil {
		return out.String(), fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(out.String()))
	}
	return out.String(), nil
}

// rstScript is the nft script that replaces the Agent's table with the RST
// rules of every fake-TCP link, in one transaction; with no rules it only
// removes the table.
func rstScript(table string, links []Link) (string, error) {
	var rules []string
	for _, link := range links {
		if link.FakeTCP == nil {
			continue
		}
		linkRules, err := link.FakeTCP.rules()
		if err != nil {
			return "", fmt.Errorf("link %q: %w", link.ID, err)
		}
		rules = append(rules, linkRules...)
	}
	var b strings.Builder
	// "add" then "delete" so the delete never fails on a missing table.
	fmt.Fprintf(&b, "table ip %s {}\ndelete table ip %s\n", table, table)
	if len(rules) == 0 {
		return b.String(), nil
	}
	fmt.Fprintf(&b, "table ip %s {\n\tchain output {\n\t\ttype filter hook output priority 0; policy accept;\n", table)
	for _, rule := range rules {
		fmt.Fprintf(&b, "\t\t%s\n", rule)
	}
	b.WriteString("\t}\n}\n")
	return b.String(), nil
}

// applyRST installs the RST rules of links (or removes the table).
// ApplyRST replaces the nftables table (family ip) with the RST rules of
// links' fake-TCP carriers; with none it removes the table. nft is the nft
// binary. The network model's anx_line ends use a table of their own, apart
// from the AnxLine section's.
func ApplyRST(ctx context.Context, runner Runner, nft, table string, links []Link) error {
	if !tableName.MatchString(table) {
		return fmt.Errorf("nftables table %q: letters, digits and _ only", table)
	}
	return applyRST(ctx, runner, valueOr(nft, DefaultNFT), table, links)
}

func applyRST(ctx context.Context, runner Runner, nft, table string, links []Link) error {
	script, err := rstScript(table, links)
	if err != nil {
		return err
	}
	_, err = runner.Run(ctx, script, nft, "-f", "-")
	return err
}
