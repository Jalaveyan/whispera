package bridgepool

import (
	"fmt"
	"testing"
	"time"
)

func newTestRegistry() *Registry {
	return NewRegistry("")
}

func makeBridge(id, addr string, bt BridgeType) *BridgeInfo {
	return &BridgeInfo{
		ID:         id,
		Address:    addr,
		Type:       bt,
		IsAlive:    true,
		Latency:    10,
		TrustLevel: 5,
		CreatedAt:  time.Now(),
		MaxUsers:   100,
	}
}

func TestBridgeRegistration(t *testing.T) {
	r := newTestRegistry()
	b := makeBridge("br-001", "1.2.3.4:8443", BridgeOperator)

	if err := r.RegisterBridge(b); err != nil {
		t.Fatalf("RegisterBridge: %v", err)
	}

	got, err := r.GetBridge("br-001")
	if err != nil {
		t.Fatalf("GetBridge: %v", err)
	}
	if got.Address != "1.2.3.4:8443" {
		t.Errorf("address mismatch: %s", got.Address)
	}
}

func TestBridgeUnregistration(t *testing.T) {
	r := newTestRegistry()
	r.RegisterBridge(makeBridge("br-002", "2.3.4.5:8443", BridgeOperator))

	if err := r.UnregisterBridge("br-002"); err != nil {
		t.Fatalf("UnregisterBridge: %v", err)
	}
	if _, err := r.GetBridge("br-002"); err == nil {
		t.Error("expected error for unregistered bridge")
	}
}

func TestBridgeDuplicateID(t *testing.T) {
	r := newTestRegistry()
	b := makeBridge("br-dup", "1.1.1.1:8443", BridgeOperator)
	r.RegisterBridge(b)

	b2 := makeBridge("br-dup", "2.2.2.2:8443", BridgeOperator)
	err := r.RegisterBridge(b2)
	if err != nil {
		t.Fatalf("re-register: %v", err)
	}
	got, _ := r.GetBridge("br-dup")
	if got.Address != "2.2.2.2:8443" {
		t.Errorf("expected updated address, got %s", got.Address)
	}
}

func TestBridgeStatusUpdate(t *testing.T) {
	r := newTestRegistry()
	r.RegisterBridge(makeBridge("br-stat", "1.2.3.4:8443", BridgeOperator))

	r.UpdateBridgeStatus("br-stat", false, 999)
	b, _ := r.GetBridge("br-stat")
	if b.IsAlive {
		t.Error("bridge should be marked dead")
	}
	if b.Latency != 999 {
		t.Errorf("latency should be 999, got %d", b.Latency)
	}

	r.UpdateBridgeStatus("br-stat", true, 15)
	b, _ = r.GetBridge("br-stat")
	if !b.IsAlive {
		t.Error("bridge should be alive after recovery")
	}
	if b.Latency != 15 {
		t.Errorf("latency should be 15, got %d", b.Latency)
	}
}

func TestGetAliveBridges(t *testing.T) {
	r := newTestRegistry()
	r.RegisterBridge(makeBridge("alive-1", "1.1.1.1:8443", BridgeOperator))
	r.RegisterBridge(makeBridge("alive-2", "2.2.2.2:8443", BridgeOperator))
	dead := makeBridge("dead-1", "3.3.3.3:8443", BridgeOperator)
	dead.IsAlive = false
	r.RegisterBridge(dead)

	alive := r.GetAliveBridges()
	if len(alive) != 2 {
		t.Errorf("expected 2 alive bridges, got %d", len(alive))
	}
	for _, b := range alive {
		if !b.IsAlive {
			t.Errorf("dead bridge %s in GetAliveBridges", b.ID)
		}
	}
}

func TestIssueValidateAccessKey(t *testing.T) {
	r := newTestRegistry()
	r.RegisterBridge(makeBridge("br-key", "1.2.3.4:8443", BridgeWhite))

	key, err := r.IssueAccessKey("br-key", "user-abc", false, time.Hour)
	if err != nil {
		t.Fatalf("IssueAccessKey: %v", err)
	}
	if key.ID == "" {
		t.Error("key ID is empty")
	}

	validated, err := r.ValidateAccessKey(key.ID)
	if err != nil {
		t.Fatalf("ValidateAccessKey: %v", err)
	}
	if validated.UserID != "user-abc" {
		t.Errorf("user mismatch: %s", validated.UserID)
	}
}

func TestOneTimeAccessKeyConsumedOnUse(t *testing.T) {
	r := newTestRegistry()
	r.RegisterBridge(makeBridge("br-otp", "1.2.3.4:8443", BridgeWhite))

	key, _ := r.IssueAccessKey("br-otp", "user-xyz", true, time.Hour)

	if _, err := r.ValidateAccessKey(key.ID); err != nil {
		t.Fatalf("first validate: %v", err)
	}

	if _, err := r.ValidateAccessKey(key.ID); err == nil {
		t.Error("one-time key should be invalid after first use")
	}
}

func TestExpiredAccessKeyRejected(t *testing.T) {
	r := newTestRegistry()
	r.RegisterBridge(makeBridge("br-exp", "1.2.3.4:8443", BridgeWhite))

	key, _ := r.IssueAccessKey("br-exp", "user-exp", false, 1*time.Millisecond)
	time.Sleep(5 * time.Millisecond)

	if _, err := r.ValidateAccessKey(key.ID); err == nil {
		t.Error("expired key should be rejected")
	}
}

func TestRevokeAccessKey(t *testing.T) {
	r := newTestRegistry()
	r.RegisterBridge(makeBridge("br-rev", "1.2.3.4:8443", BridgeWhite))

	key, _ := r.IssueAccessKey("br-rev", "user-rev", false, time.Hour)

	if err := r.RevokeAccessKey(key.ID); err != nil {
		t.Fatalf("RevokeAccessKey: %v", err)
	}
	if _, err := r.ValidateAccessKey(key.ID); err == nil {
		t.Error("revoked key should be invalid")
	}
}

func TestCleanExpiredAccessKeys(t *testing.T) {
	r := newTestRegistry()
	r.RegisterBridge(makeBridge("br-clean", "1.2.3.4:8443", BridgeWhite))

	for i := 0; i < 5; i++ {
		_, _ = r.IssueAccessKey("br-clean", fmt.Sprintf("user-%d", i), false, 1*time.Millisecond)
	}
	time.Sleep(5 * time.Millisecond)
	_, _ = r.IssueAccessKey("br-clean", "user-alive-1", false, time.Hour)
	_, _ = r.IssueAccessKey("br-clean", "user-alive-2", false, time.Hour)

	r.CleanExpiredAccessKeys()

	keys := r.GetAccessKeysForBridge("br-clean")
	if len(keys) != 2 {
		t.Errorf("expected 2 keys after cleanup, got %d", len(keys))
	}
}

func TestWhiteBridgeFiltering(t *testing.T) {
	r := newTestRegistry()
	r.RegisterBridge(makeBridge("op-1", "1.1.1.1:8443", BridgeOperator))
	r.RegisterBridge(makeBridge("white-1", "2.2.2.2:8443", BridgeWhite))
	r.RegisterBridge(makeBridge("white-2", "3.3.3.3:8443", BridgeWhite))
	r.RegisterBridge(makeBridge("comm-1", "4.4.4.4:8443", BridgeCommunity))

	whites := r.GetWhiteBridges()
	if len(whites) != 2 {
		t.Errorf("expected 2 white bridges, got %d", len(whites))
	}
	for _, b := range whites {
		if b.Type != BridgeWhite {
			t.Errorf("non-white bridge in GetWhiteBridges: %s (%s)", b.ID, b.Type)
		}
	}
}

func TestGetBridgesForUser(t *testing.T) {
	r := newTestRegistry()
	for i := 0; i < 10; i++ {
		b := makeBridge(
			fmt.Sprintf("br-%02d", i),
			fmt.Sprintf("10.0.0.%d:8443", i+1),
			BridgeOperator,
		)
		b.Latency = (i + 1) * 5
		r.RegisterBridge(b)
	}

	set1 := r.GetBridgesForUser("user-alpha", 3)
	set2 := r.GetBridgesForUser("user-alpha", 3)
	set3 := r.GetBridgesForUser("user-beta", 3)

	if len(set1) != 3 {
		t.Errorf("expected 3 bridges for user, got %d", len(set1))
	}

	ids1 := bridgeIDs(set1)
	ids2 := bridgeIDs(set2)
	for i := range ids1 {
		if ids1[i] != ids2[i] {
			t.Errorf("bridge selection not deterministic for same user (pos %d: %s vs %s)", i, ids1[i], ids2[i])
		}
	}

	ids3 := bridgeIDs(set3)
	allSame := true
	for i := range ids1 {
		if i >= len(ids3) || ids1[i] != ids3[i] {
			allSame = false
			break
		}
	}
	if allSame {
		t.Error("different users should get different bridge shards")
	}
}

func bridgeIDs(bridges []*BridgeInfo) []string {
	ids := make([]string, len(bridges))
	for i, b := range bridges {
		ids[i] = b.ID
	}
	return ids
}

func TestBridgeLoadTracking(t *testing.T) {
	r := newTestRegistry()
	r.RegisterBridge(makeBridge("br-load", "1.2.3.4:8443", BridgeOperator))

	r.UpdateBridgeLoad("br-load", 0.75, 75)
	b, _ := r.GetBridge("br-load")
	if b.Load != 0.75 {
		t.Errorf("load should be 0.75, got %f", b.Load)
	}
	if b.CurUsers != 75 {
		t.Errorf("cur_users should be 75, got %d", b.CurUsers)
	}
}

func TestBridgeStats(t *testing.T) {
	r := newTestRegistry()
	r.RegisterBridge(makeBridge("s1", "1.1.1.1:8443", BridgeOperator))
	r.RegisterBridge(makeBridge("s2", "2.2.2.2:8443", BridgeCommunity))
	dead := makeBridge("s3", "3.3.3.3:8443", BridgeOperator)
	dead.IsAlive = false
	r.RegisterBridge(dead)

	stats := r.BridgeStats()

	if stats["total"].(int) != 3 {
		t.Errorf("total should be 3, got %v", stats["total"])
	}
	if stats["alive"].(int) != 2 {
		t.Errorf("alive should be 2, got %v", stats["alive"])
	}
}

func TestAdminSSHKey(t *testing.T) {
	r := newTestRegistry()
	r.SetAdminSSHKey("ssh-ed25519 AAAA... admin@whispera")

	got := r.GetAdminSSHKey()
	if got != "ssh-ed25519 AAAA... admin@whispera" {
		t.Errorf("admin SSH key mismatch: %s", got)
	}
}

func TestBridgeFailoverRecovery(t *testing.T) {
	r := newTestRegistry()
	for i := 0; i < 3; i++ {
		r.RegisterBridge(makeBridge(
			fmt.Sprintf("failover-%d", i),
			fmt.Sprintf("10.0.%d.1:8443", i),
			BridgeOperator,
		))
	}

	all := r.GetAllBridges()
	for _, b := range all {
		r.UpdateBridgeStatus(b.ID, false, 9999)
	}
	if alive := r.GetAliveBridges(); len(alive) != 0 {
		t.Errorf("expected 0 alive, got %d", len(alive))
	}

	r.UpdateBridgeStatus("failover-1", true, 20)
	alive := r.GetAliveBridges()
	if len(alive) != 1 || alive[0].ID != "failover-1" {
		t.Errorf("expected exactly failover-1 to recover, got %v", alive)
	}
}
