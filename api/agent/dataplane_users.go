package agent

import (
	"context"
	"sort"
	"time"

	agentv1pb "github.com/AnixOps/anix-control/sdk/api/agent/v1"
	log "github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"
)

// Users from the stream (users.v1; PROTOCOL.md, "Users"). Control sends the
// node's user changes after the Agent's cursor as UserDelta pages: a full
// set (full, in pages up to last_page) when it cannot resume from the
// cursor, else deltas carrying each changed user's current state. The data
// plane keeps the node's desired user set and its cursor, hands the whole
// set to the UsersApplier after each complete delta (the node adds and
// removes what changed, without restarting the core), retries a failed
// application, and stores the set so a restarted Agent resumes from its
// cursor.

// usersRetryInterval spaces out retries of a user set the node could not
// apply (a variable for tests).
var usersRetryInterval = 30 * time.Second

const (
	// usersSaveInterval batches writes of users.pb: a cursor stored a
	// little behind only makes Control resend changes the set already has,
	// which apply again idempotently.
	usersSaveInterval = 2 * time.Second
	// maxPendingUserPages bounds the pages of one delta held until its
	// last_page (2.5 million users at Control's 500 per page).
	maxPendingUserPages = 5000
)

// UserSet is the node's whole user set at a change-log cursor.
type UserSet struct {
	// Cursor is the change-log position the set reflects; 0 when Control's
	// change log was empty.
	Cursor uint64
	// Users are the users the node serves, by ascending user_id.
	Users []*agentv1pb.NodeUser
}

// UsersApplier applies user sets (users.v1).
type UsersApplier interface {
	// ApplyUsers makes the node serve exactly set.Users. Calls come from
	// one goroutine, after every complete delta (several deltas that
	// arrive together are applied as one set). A failed set is offered
	// again, as the newest set, until one applies.
	ApplyUsers(ctx context.Context, set UserSet) error
}

// usersState is the users part of the data plane, guarded by DataPlane.mu.
type usersState struct {
	// has is set once the data plane holds a set (restored, taken at
	// startup or received after Activate).
	has    bool
	cursor uint64
	set    map[uint64]*agentv1pb.NodeUser
	// version counts the changes to set; applied is the version the node
	// last applied.
	version uint64
	applied uint64
	// persisted is the set read from users.pb at load.
	persisted *UserSet
	// pages holds the pages of the delta being received on pagesSession.
	pages        []*agentv1pb.UserDelta
	pagesSession string
	// queue holds complete deltas not yet folded into set.
	queue   []*agentv1pb.UserDelta
	arrived chan struct{}
	dirty   bool
	savedAt time.Time
	retryAt time.Time
	lastErr string
}

func (u *usersState) userSet() UserSet {
	users := make([]*agentv1pb.NodeUser, 0, len(u.set))
	for _, user := range u.set {
		users = append(users, user)
	}
	sort.Slice(users, func(i, j int) bool { return users[i].GetUserId() < users[j].GetUserId() })
	return UserSet{Cursor: u.cursor, Users: users}
}

// fold applies a complete delta to the set.
func (u *usersState) fold(delta *agentv1pb.UserDelta) {
	if delta.GetFull() || u.set == nil {
		u.set = make(map[uint64]*agentv1pb.NodeUser, len(delta.GetUpserts()))
	}
	if !delta.GetFull() {
		for _, id := range delta.GetRemovedUserIds() {
			delete(u.set, id)
		}
	}
	for _, user := range delta.GetUpserts() {
		if user.GetUserId() == 0 {
			continue
		}
		u.set[user.GetUserId()] = user
	}
	u.cursor = delta.GetCursor()
	u.has = true
	u.version++
	u.dirty = true
}

// loadUsers reads users.pb.
func (d *DataPlane) loadUsers() {
	stored, err := d.config.State.LoadUsers()
	if err != nil {
		d.logger().WithError(err).Warn("Discarding the stored user set")
		_ = d.config.State.DiscardUsers()
		return
	}
	if stored != nil {
		d.users.persisted = &UserSet{Cursor: stored.GetCursor(), Users: stored.GetUpserts()}
	}
}

// helloUsersCursor is Hello.users_cursor: the cursor of the set the data
// plane holds, 0 without one.
func (d *DataPlane) helloUsersCursor() uint64 {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.users.has {
		return 0
	}
	return d.users.cursor
}

// PersistedUsers is the user set the node last held, from its state, nil
// without one. The node serves it at startup (RestoreUsers) without
// waiting for Control.
func (d *DataPlane) PersistedUsers() *UserSet {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.users.persisted == nil {
		return nil
	}
	set := *d.users.persisted
	return &set
}

// RestoreUsers records that the node serves the persisted set: Hello
// reports its cursor, and Control resumes from it.
func (d *DataPlane) RestoreUsers(set UserSet) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.users.set = make(map[uint64]*agentv1pb.NodeUser, len(set.Users))
	for _, user := range set.Users {
		d.users.set[user.GetUserId()] = user
	}
	d.users.cursor, d.users.has = set.Cursor, true
	d.users.version++
	d.users.applied = d.users.version
}

// DiscardPersistedUsers drops the persisted set after the node could not
// serve it; Hello reports no cursor and Control sends the whole set.
func (d *DataPlane) DiscardPersistedUsers() {
	d.mu.Lock()
	d.users.persisted = nil
	d.mu.Unlock()
	if err := d.config.State.DiscardUsers(); err != nil {
		d.logger().WithError(err).Warn("Could not remove the stored user set")
	}
}

// TakeUsers waits for the node's whole user set from Control and takes it,
// for the node's startup (a Hello without a cursor makes Control send it).
// The node answers it with UsersResult.
func (d *DataPlane) TakeUsers(ctx context.Context) (UserSet, error) {
	for {
		d.mu.Lock()
		arrived := d.users.arrived
		for index, delta := range d.users.queue {
			if !delta.GetFull() {
				continue
			}
			// Changes queued before the set are part of it.
			d.users.queue = d.users.queue[index+1:]
			d.users.fold(delta)
			set := d.users.userSet()
			d.mu.Unlock()
			return set, nil
		}
		d.mu.Unlock()
		select {
		case <-ctx.Done():
			return UserSet{}, ctx.Err()
		case <-d.ctx.Done():
			return UserSet{}, d.ctx.Err()
		case <-arrived:
		}
	}
}

// UsersResult answers a set the node applied itself (TakeUsers); a failed
// one is offered to the UsersApplier again after Activate.
func (d *DataPlane) UsersResult(set UserSet, err error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if err != nil {
		d.users.lastErr = err.Error()
		d.users.retryAt = d.now()
		return
	}
	if d.users.cursor == set.Cursor {
		d.users.applied = d.users.version
	}
}

// receiveUsers takes a UserDelta page from the session's receive loop. The
// pages of a delta are held until its last_page; a session that ends
// before it leaves no change, and the Agent's cursor stays where it was.
func (d *DataPlane) receiveUsers(sessionID string, delta *agentv1pb.UserDelta) {
	if delta == nil {
		return
	}
	d.mu.Lock()
	if d.users.pagesSession != sessionID {
		d.users.pages, d.users.pagesSession = nil, sessionID
	}
	if len(d.users.pages) >= maxPendingUserPages {
		d.users.pages = nil
		d.mu.Unlock()
		d.logger().Warn("A user delta from Control exceeds the page limit; dropping it and resynchronizing")
		d.client.recycleSession()
		return
	}
	d.users.pages = append(d.users.pages, proto.Clone(delta).(*agentv1pb.UserDelta))
	if !delta.GetLastPage() {
		d.mu.Unlock()
		return
	}
	pages := d.users.pages
	d.users.pages = nil
	assembled := &agentv1pb.UserDelta{Cursor: delta.GetCursor(), Full: pages[0].GetFull(), LastPage: true}
	for _, page := range pages {
		assembled.Upserts = append(assembled.Upserts, page.GetUpserts()...)
		assembled.RemovedUserIds = append(assembled.RemovedUserIds, page.GetRemovedUserIds()...)
	}
	d.users.queue = append(d.users.queue, assembled)
	close(d.users.arrived)
	d.users.arrived = make(chan struct{})
	d.mu.Unlock()
	d.signal()
}

// dropUserPages forgets the incomplete delta of a session that ended.
// Called with d.mu held.
func (d *DataPlane) dropUserPagesLocked(sessionID string) {
	if d.users.pagesSession == sessionID {
		d.users.pages, d.users.pagesSession = nil, ""
	}
}

// applyPendingUsers folds the queued deltas into the set and hands the set
// to the applier, after Activate.
func (d *DataPlane) applyPendingUsers() {
	if d.config.Users == nil {
		return
	}
	d.mu.Lock()
	if !d.active {
		d.mu.Unlock()
		return
	}
	for _, delta := range d.users.queue {
		d.users.fold(delta)
	}
	d.users.queue = nil
	due := d.users.has && d.users.applied != d.users.version &&
		(d.users.retryAt.IsZero() || !d.now().Before(d.users.retryAt))
	if !due {
		d.mu.Unlock()
		return
	}
	set, version := d.users.userSet(), d.users.version
	d.mu.Unlock()

	err := d.config.Users.ApplyUsers(d.ctx, set)
	if d.ctx.Err() != nil {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	entry := d.logger().WithFields(log.Fields{"users_cursor": set.Cursor, "users": len(set.Users)})
	if err != nil {
		d.counters.usersFailed.Add(1)
		d.users.lastErr = err.Error()
		d.users.retryAt = d.now().Add(usersRetryInterval)
		entry.WithError(err).Error("Could not apply the user set from Control; retrying")
		return
	}
	d.counters.usersApplied.Add(1)
	d.users.lastErr, d.users.retryAt = "", time.Time{}
	if d.users.version == version {
		d.users.applied = version
	}
	entry.Debug("Applied the user set from Control")
}

// saveUsers writes users.pb when the set changed: at most every
// usersSaveInterval, or at once with force (on close).
func (d *DataPlane) saveUsers(force bool) {
	if d.config.Users == nil {
		return
	}
	d.mu.Lock()
	if !d.users.dirty || (!force && d.now().Sub(d.users.savedAt) < usersSaveInterval) {
		d.mu.Unlock()
		return
	}
	set := d.users.userSet()
	d.users.dirty, d.users.savedAt = false, d.now()
	d.mu.Unlock()
	if err := d.config.State.SaveUsers(set.Cursor, set.Users); err != nil {
		d.mu.Lock()
		d.users.dirty = true
		d.mu.Unlock()
		d.logger().WithError(err).Warn("Could not store the user set; a restart resumes from an older cursor")
	}
}

// usersWake is when the worker has users work to do without a signal: a
// retry or a delayed save. Zero for none. Called with d.mu held.
func (d *DataPlane) usersWakeLocked() time.Time {
	var next time.Time
	if d.config.Users == nil {
		return next
	}
	if d.users.dirty {
		next = d.users.savedAt.Add(usersSaveInterval)
	}
	if d.active && d.users.has && d.users.applied != d.users.version && !d.users.retryAt.IsZero() {
		if next.IsZero() || d.users.retryAt.Before(next) {
			next = d.users.retryAt
		}
	}
	return next
}
