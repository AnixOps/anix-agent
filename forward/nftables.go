package forward

import (
	"context"
	"os/exec"
	"strings"

	log "github.com/sirupsen/logrus"
)

const (
	// retiredNftablesFamily and retiredNftablesTable are the table the
	// removed nftables driver kept its DNAT rules in.
	retiredNftablesFamily = "inet"
	retiredNftablesTable  = "anixops_fwd"
	// retiredQdiscHandle is the root qdisc the removed driver put on the
	// rate-limited egress interfaces (tc HTB).
	retiredQdiscHandle = "af00:"
)

// RetireNftables removes what a previous Agent's nftables driver left in the
// kernel: its table (the DNAT rules, which kept forwarding after the Agent
// stopped) and its tc root qdisc. Nothing happens on a host that never ran
// the driver. Failures are logged and ignored: the rules are only stale.
func RetireNftables(ctx context.Context, settings NftablesSettings) {
	nft, tc := settings.NFT, settings.TC
	if nft == "" {
		nft = "nft"
	}
	if tc == "" {
		tc = "tc"
	}
	logger := log.WithField("component", "forward")
	// #nosec G204 -- the binaries come from the Agent's configuration.
	if exec.CommandContext(ctx, nft, "list", "table", retiredNftablesFamily, retiredNftablesTable).Run() == nil {
		if out, err := exec.CommandContext(ctx, nft, "delete", "table", retiredNftablesFamily, retiredNftablesTable).CombinedOutput(); err != nil {
			logger.WithError(err).WithField("output", string(out)).Warn("Could not delete the retired nftables forward table")
		} else {
			logger.Info("Retired nftables forwarding: deleted table " + retiredNftablesFamily + " " + retiredNftablesTable + " (its routes run on the network model)")
		}
	}
	// #nosec G204 -- see above.
	out, err := exec.CommandContext(ctx, tc, "qdisc", "show").Output()
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		// "qdisc htb af00: dev eth0 root refcnt 2 ..."
		if len(fields) < 5 || fields[0] != "qdisc" || fields[2] != retiredQdiscHandle || fields[3] != "dev" {
			continue
		}
		// #nosec G204 -- see above.
		if out, err := exec.CommandContext(ctx, tc, "qdisc", "del", "dev", fields[4], "root", "handle", retiredQdiscHandle).CombinedOutput(); err != nil {
			logger.WithError(err).WithFields(log.Fields{"dev": fields[4], "output": string(out)}).Warn("Could not delete the retired tc qdisc")
		}
	}
}
