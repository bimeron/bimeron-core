//go:build windows

package systemvpn

import (
	"context"
	"os"
	"strconv"
	"testing"
	"time"
)

// Opt-in only: owns one native RAS handle in a disposable interactive account.
// No credentials/certificates are supplied or changed by this fixture.
func TestWindowsIKEv2ActivePreparationRefusal(t *testing.T) {
	if os.Getenv("BIMERON_IKEV2_ACTIVE_PREPARATION_LIVE") != "1" {
		t.Skip("controlled disposable RAS fixture required")
	}
	cfg := Config{WindowsProfile: os.Getenv("BIMERON_IKEV2_ACTIVE_PROFILE"), ServerName: os.Getenv("BIMERON_IKEV2_PROFILE_TEST_SERVER")}
	ctx, cancel := context.WithTimeout(context.Background(), 75*time.Second)
	defer cancel()
	session, err := Open(ctx, cfg)
	if err != nil {
		t.Fatal("controlled existing-profile dial failed", err)
	}
	defer func() {
		if session.Close() != nil {
			t.Error("owned test RAS cleanup failed; manual review required")
		}
	}()
	fresh := Config{WindowsProfile: "Bimeron active refusal " + strconv.FormatInt(time.Now().UnixNano(), 10), ServerName: cfg.ServerName}
	if _, err := PrepareProfile(fresh, true, false); err == nil || err.Error() != "ikev2_existing_ras_connection" {
		t.Fatal("active RAS did not refuse apply")
	}
	if _, err := PrepareProfile(cfg, false, true); err == nil || err.Error() != "ikev2_existing_ras_connection" {
		t.Fatal("active RAS did not refuse remove")
	}
	status, err := session.driver.status(session.handle)
	if err != nil || status.state != stateConnected {
		t.Fatal("preparation changed/adopted the existing connection")
	}
}
