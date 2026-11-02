package keyresolve

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/ohstr/ncli/client"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func withTempConfigDir(t *testing.T) {
	t.Helper()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
}

func newTestCmd() *cobra.Command {
	return &cobra.Command{Use: "test"}
}

// addSoleVaultEntry creates a vault and saves one entry under label,
// setting vault.password so ResolveSigningKey's unlock doesn't try to
// prompt. Returns the entry's own private key, for asserting against.
func addSoleVaultEntry(t *testing.T, label string) string {
	t.Helper()
	_, vaultPrivHex, err := client.CreateVaultIdentity("hunter2")
	if err != nil {
		t.Fatalf("CreateVaultIdentity() error = %v", err)
	}
	id, err := client.GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity() error = %v", err)
	}
	if _, err := client.AddVaultEntry(vaultPrivHex, label, id.PrivKeyHex); err != nil {
		t.Fatalf("AddVaultEntry() error = %v", err)
	}
	viper.Set("vault.password", "hunter2")
	t.Cleanup(viper.Reset)
	return id.PrivKeyHex
}

func TestResolveIdentity_ExplicitNsec(t *testing.T) {
	withTempConfigDir(t)
	id, err := client.GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity() error = %v", err)
	}

	got, err := ResolveIdentity(newTestCmd(), id.Nsec, "test.identity")
	if err != nil {
		t.Fatalf("ResolveIdentity() error = %v", err)
	}
	if got != id.PrivKeyHex {
		t.Fatalf("ResolveIdentity() = %q, want %q", got, id.PrivKeyHex)
	}
}

func TestResolveIdentity_NoIdentityNoVault(t *testing.T) {
	withTempConfigDir(t)

	if _, err := ResolveIdentity(newTestCmd(), "", "test.identity"); err == nil {
		t.Fatal("ResolveIdentity() with no flag/config/vault = nil error, want an error")
	}
}

func TestResolveIdentity_SoleVaultEntryAutoDetected(t *testing.T) {
	withTempConfigDir(t)
	wantPriv := addSoleVaultEntry(t, "alice")

	got, err := ResolveIdentity(newTestCmd(), "", "test.identity")
	if err != nil {
		t.Fatalf("ResolveIdentity() error = %v", err)
	}
	if got != wantPriv {
		t.Fatalf("ResolveIdentity() = %q, want %q", got, wantPriv)
	}
}

func TestResolveIdentity_AmbiguousVaultEntries(t *testing.T) {
	withTempConfigDir(t)
	_, vaultPrivHex, err := client.CreateVaultIdentity("hunter2")
	if err != nil {
		t.Fatalf("CreateVaultIdentity() error = %v", err)
	}
	for _, label := range []string{"alice", "bob"} {
		id, err := client.GenerateIdentity()
		if err != nil {
			t.Fatalf("GenerateIdentity() error = %v", err)
		}
		if _, err := client.AddVaultEntry(vaultPrivHex, label, id.PrivKeyHex); err != nil {
			t.Fatalf("AddVaultEntry() error = %v", err)
		}
	}

	if _, err := ResolveIdentity(newTestCmd(), "", "test.identity"); err == nil {
		t.Fatal("ResolveIdentity() with 2 vault entries and no flag/config = nil error, want an error")
	}
}

func TestResolveIdentityOptional_NoIdentityNoVault(t *testing.T) {
	withTempConfigDir(t)

	got, err := ResolveIdentityOptional(newTestCmd(), "", "test.identity", false)
	if err != nil {
		t.Fatalf("ResolveIdentityOptional() error = %v, want nil", err)
	}
	if got != "" {
		t.Fatalf("ResolveIdentityOptional() = %q, want \"\"", got)
	}
}

func TestResolveIdentityOptional_AmbiguousVaultEntriesSkipped(t *testing.T) {
	withTempConfigDir(t)
	_, vaultPrivHex, err := client.CreateVaultIdentity("hunter2")
	if err != nil {
		t.Fatalf("CreateVaultIdentity() error = %v", err)
	}
	for _, label := range []string{"alice", "bob"} {
		id, err := client.GenerateIdentity()
		if err != nil {
			t.Fatalf("GenerateIdentity() error = %v", err)
		}
		if _, err := client.AddVaultEntry(vaultPrivHex, label, id.PrivKeyHex); err != nil {
			t.Fatalf("AddVaultEntry() error = %v", err)
		}
	}

	got, err := ResolveIdentityOptional(newTestCmd(), "", "test.identity", false)
	if err != nil {
		t.Fatalf("ResolveIdentityOptional() with ambiguous vault error = %v, want nil (skip, don't block)", err)
	}
	if got != "" {
		t.Fatalf("ResolveIdentityOptional() = %q, want \"\" (ambiguous vault should be skipped, not guessed)", got)
	}
}

func TestResolveIdentityOptional_SoleVaultEntryAutoDetected(t *testing.T) {
	withTempConfigDir(t)
	wantPriv := addSoleVaultEntry(t, "alice")

	got, err := ResolveIdentityOptional(newTestCmd(), "", "test.identity", false)
	if err != nil {
		t.Fatalf("ResolveIdentityOptional() error = %v", err)
	}
	if got != wantPriv {
		t.Fatalf("ResolveIdentityOptional() = %q, want %q", got, wantPriv)
	}
}

func TestResolveIdentityOptional_ExplicitBadIdentityStillErrors(t *testing.T) {
	withTempConfigDir(t)

	if _, err := ResolveIdentityOptional(newTestCmd(), "not-a-real-identity-at-all", "test.identity", false); err == nil {
		t.Fatal("ResolveIdentityOptional() with an explicit but unresolvable --identity = nil error, want an error (typos must not be swallowed)")
	}
}

func TestResolveIdentityOptional_ExplicitViaConfigKeyStillErrors(t *testing.T) {
	withTempConfigDir(t)
	viper.Set("test.identity", "not-a-real-identity-at-all")
	t.Cleanup(viper.Reset)

	if _, err := ResolveIdentityOptional(newTestCmd(), "", "test.identity", false); err == nil {
		t.Fatal("ResolveIdentityOptional() with an explicit but unresolvable config identity = nil error, want an error")
	}
}

// --- interactive secret reads (issue #205) ---

// TestReadSecretTTY_UsesControllingTerminal: when the controlling terminal
// opens, the secret is read from it and stdin is never consulted -- the fix
// for a piped stdin (`event new | publish -e - --signer <label>`).
func TestReadSecretTTY_UsesControllingTerminal(t *testing.T) {
	tty, err := os.CreateTemp(t.TempDir(), "tty")
	if err != nil {
		t.Fatalf("CreateTemp() error = %v", err)
	}
	t.Cleanup(func() { _ = tty.Close() })

	open := func() (*os.File, error) { return tty, nil }
	read := func(fd int) (string, error) {
		if fd != int(tty.Fd()) {
			t.Fatalf("read fd = %d, want the controlling-terminal fd %d", fd, tty.Fd())
		}
		return "hunter2", nil
	}
	stdinTTY := func() bool {
		t.Fatal("stdin must not be consulted when the controlling terminal opens")
		return false
	}

	got, err := readSecretTTY(open, read, stdinTTY)
	if err != nil {
		t.Fatalf("readSecretTTY() error = %v", err)
	}
	if got != "hunter2" {
		t.Fatalf("readSecretTTY() = %q, want %q", got, "hunter2")
	}
}

// TestReadSecretTTY_FallsBackToStdinWhenItIsATerminal: if the controlling
// terminal can't be opened but fd 0 itself is a terminal, read fd 0 -- the
// pre-existing behavior, preserved.
func TestReadSecretTTY_FallsBackToStdinWhenItIsATerminal(t *testing.T) {
	open := func() (*os.File, error) { return nil, errors.New("no /dev/tty") }
	read := func(fd int) (string, error) {
		if fd != int(os.Stdin.Fd()) {
			t.Fatalf("read fd = %d, want stdin fd %d", fd, os.Stdin.Fd())
		}
		return "from-stdin", nil
	}

	got, err := readSecretTTY(open, read, func() bool { return true })
	if err != nil {
		t.Fatalf("readSecretTTY() error = %v", err)
	}
	if got != "from-stdin" {
		t.Fatalf("readSecretTTY() = %q, want %q", got, "from-stdin")
	}
}

// TestReadSecretTTY_NoTerminalReturnsClearError: no controlling terminal and
// a non-terminal stdin yields the actionable ErrNoTerminal, not the cryptic
// "inappropriate ioctl for device" from a raw termios read (issue #205).
func TestReadSecretTTY_NoTerminalReturnsClearError(t *testing.T) {
	open := func() (*os.File, error) { return nil, errors.New("no /dev/tty") }
	read := func(int) (string, error) {
		t.Fatal("must not attempt a read when no terminal is available")
		return "", nil
	}

	_, err := readSecretTTY(open, read, func() bool { return false })
	if !errors.Is(err, ErrNoTerminal) {
		t.Fatalf("readSecretTTY() error = %v, want ErrNoTerminal", err)
	}
	if strings.Contains(err.Error(), "ioctl") {
		t.Fatalf("readSecretTTY() surfaced a cryptic ioctl error: %v", err)
	}
}

// TestResolveVaultPassword_EnvTakesPrecedence: NCLI_VAULT_PASSWORD
// (vault.password) short-circuits before any prompt, in interactive mode.
func TestResolveVaultPassword_EnvTakesPrecedence(t *testing.T) {
	viper.Reset()
	viper.Set("vault.password", "hunter2")
	t.Cleanup(viper.Reset)

	got, err := ResolveVaultPassword(false, "Vault password: ")
	if err != nil {
		t.Fatalf("ResolveVaultPassword() error = %v", err)
	}
	if got != "hunter2" {
		t.Fatalf("ResolveVaultPassword() = %q, want %q", got, "hunter2")
	}
}

// TestResolveVaultPassword_JSONNeverPrompts: --json with no env never
// prompts; it returns a clear "set NCLI_VAULT_PASSWORD" error.
func TestResolveVaultPassword_JSONNeverPrompts(t *testing.T) {
	viper.Reset()
	t.Cleanup(viper.Reset)

	_, err := ResolveVaultPassword(true, "Vault password: ")
	if err == nil {
		t.Fatal("ResolveVaultPassword(jsonMode=true) with no env = nil error, want an error (it must never prompt)")
	}
	if !strings.Contains(err.Error(), "NCLI_VAULT_PASSWORD") {
		t.Fatalf("ResolveVaultPassword() error = %v, want it to name NCLI_VAULT_PASSWORD", err)
	}
}
