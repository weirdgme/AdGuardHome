package aghnet

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"

	"github.com/AdguardTeam/AdGuardHome/internal/aghos"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/netutil"
)

// ARPDB

// ARPDB stores and refreshes the network neighborhood reported by ARP.
type ARPDB interface {
	// Refresh tries to update the stored data.  It must be safe for concurrent
	// use.
	Refresh() (err error)

	// Neighbors returnes the last set of data reported by ARP.  Both the method
	// and it's result must be safe for concurrent use.
	Neighbors() (ns []Neighbor)
}

// NewARPDB returns the ARPDB properly initialized for the OS.
func NewARPDB() (arp ARPDB, err error) {
	arp = newARPDB()

	err = arp.Refresh()
	if err != nil {
		return nil, fmt.Errorf("arpdb initial refresh: %w", err)
	}

	return arp, nil
}

// Empty ARPDB implementation

// EmptyARPDB is the ARPDB implementation that does nothing.
type EmptyARPDB struct{}

// type check
var _ ARPDB = EmptyARPDB{}

// Refresh implements the ARPDB interface for EmptyARPContainer.
func (EmptyARPDB) Refresh() (err error) { return nil }

// Neighbors implements the ARPDB interface for EmptyARPContainer.
func (EmptyARPDB) Neighbors() (ns []Neighbor) { return nil }

// ARPDB Helper Types

// Neighbor is the pair of IP address and MAC address reported by ARP.
type Neighbor struct {
	// Name is the hostname of the neighbor.  Empty name is valid since not each
	// implementation of ARP is able to retrieve that.
	Name string

	// IP contains either IPv4 or IPv6.
	IP net.IP

	// MAC contains the hardware address.
	MAC net.HardwareAddr
}

// Clone returns the deep copy of n.
func (n Neighbor) Clone() (clone Neighbor) {
	return Neighbor{
		Name: n.Name,
		IP:   netutil.CloneIP(n.IP),
		MAC:  netutil.CloneMAC(n.MAC),
	}
}

// neighs is the helper type that stores neighbors to avoid copying its methods
// among all the ARPDB implementations.
type neighs struct {
	mu *sync.RWMutex
	ns []Neighbor
}

// len returns the length of the neighbors slice.  It's safe for concurrent use.
func (ns *neighs) len() (l int) {
	ns.mu.RLock()
	defer ns.mu.RUnlock()

	return len(ns.ns)
}

// clone returns a deep copy of the underlying neighbors slice.  It's safe for
// concurrent use.
func (ns *neighs) clone() (cloned []Neighbor) {
	ns.mu.RLock()
	defer ns.mu.RUnlock()

	cloned = make([]Neighbor, len(ns.ns))
	for i, n := range ns.ns {
		cloned[i] = n.Clone()
	}

	return cloned
}

// reset replaces the underlying slice with the new one.  It's safe for
// concurrent use.
func (ns *neighs) reset(with []Neighbor) {
	ns.mu.Lock()
	defer ns.mu.Unlock()

	ns.ns = with
}

// Command ARPDB

// parseF parses the text from sc as if it'd be an output of some ARP-related
// command.  lenHint is a hint for the size of the allocated slice of Neighbors.
type parseF func(sc *bufio.Scanner, lenHint int) (ns []Neighbor)

type runcmdF func() (r io.Reader, err error)

// cmdARPDB is the implementation of the ARPDB that uses command line to
// retrieve data.
type cmdARPDB struct {
	parse  parseF
	runcmd runcmdF
	ns     *neighs
}

// type check
var _ ARPDB = (*cmdARPDB)(nil)

// rc runs the cmd with it's args and returns the result wrapped with io.Reader.
// The error is returned either if the exit code retured by command not equals 0
// or the execution itself failed.
func rc(cmd string, args ...string) (r io.Reader, err error) {
	var code int
	var out string
	code, out, err = aghos.RunCommand(cmd, args...)
	if err != nil {
		return nil, err
	} else if code != 0 {
		return nil, fmt.Errorf("unexpected exit code %d", code)
	}

	return strings.NewReader(out), nil
}

// Refresh implements the ARPDB interface for *cmdARPDB.
func (arp *cmdARPDB) Refresh() (err error) {
	defer func() { err = errors.Annotate(err, "cmd arpdb: %w") }()

	var r io.Reader
	r, err = arp.runcmd()
	if err != nil {
		return fmt.Errorf("running command: %w", err)
	}

	sc := bufio.NewScanner(r)
	ns := arp.parse(sc, arp.ns.len())
	if err = sc.Err(); err != nil {
		return fmt.Errorf("scanning the output: %w", err)
	}

	arp.ns.reset(ns)

	return nil
}

// Neighbors implements the ARPDB interface for *cmdARPDB.
func (arp *cmdARPDB) Neighbors() (ns []Neighbor) {
	return arp.ns.clone()
}

// Composite ARPDB

// compARPDB is the ARPDB that combines several ARPDB implementations and
// consequently switches between those.
type compARPDB struct {
	arps []ARPDB
	last int
}

func newCompARPDB(arps ...ARPDB) (arp *compARPDB) {
	return &compARPDB{
		arps: arps,
		last: 0,
	}
}

// type check
var _ ARPDB = (*compARPDB)(nil)

// Refresh implements the ARPDB interface for *compARPDB.
func (arp *compARPDB) Refresh() (err error) {
	l := len(arp.arps)
	var errs []error
	for i, last := 0, arp.last; i < l; i, last = i+1, (arp.last+1)%l {
		err = arp.arps[last].Refresh()
		if err == nil {
			arp.last = last

			return nil
		}

		errs = append(errs, err)
	}

	if len(errs) > 0 {
		err = errors.List("all implementations failed", errs...)
	}

	return err
}

// Neighbors implements the ARPDB interface for *compARPDB.
func (arp *compARPDB) Neighbors() (ns []Neighbor) {
	if l := len(arp.arps); l > 0 && arp.last < l {
		return arp.arps[arp.last].Neighbors()
	}

	return nil
}
