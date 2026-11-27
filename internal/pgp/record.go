package pgp

import (
	"fmt"
	"time"

	"github.com/licentiapoetica/yking/internal/keyring"
	"github.com/licentiapoetica/yking/internal/plan"
)

// RecordPlan records the subkeys now on the key with serial; an earlier
// record for the same slot is replaced.
func RecordPlan(krPath, serial string, entries []keyring.PGPKey, now time.Time) (*plan.Plan, error) {
	base, err := plan.ReadBase(krPath)
	if err != nil {
		return nil, err
	}
	if !base.Exists {
		return nil, fmt.Errorf("%s does not exist; register the key first", krPath)
	}
	kr, err := keyring.Parse(base.Data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", krPath, err)
	}
	k := kr.Find(serial)
	if k == nil {
		return nil, fmt.Errorf("key %s is not registered", serial)
	}
	for _, e := range entries {
		kept := k.PGP[:0]
		for _, p := range k.PGP {
			if p.Slot != e.Slot {
				kept = append(kept, p)
			}
		}
		k.PGP = append(kept, e)
	}
	content, err := kr.Encode()
	if err != nil {
		return nil, err
	}
	p := plan.New(fmt.Sprintf("record PGP subkeys on key %q", k.Label), now)
	p.Replace(base, content, 0o644)
	if p.Empty() {
		return nil, plan.ErrNoChanges
	}
	return p, nil
}
