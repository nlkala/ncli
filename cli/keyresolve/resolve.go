// Package keyresolve holds identity-resolution helpers shared by every
// command that turns a vault label/nsec/npub/hex/nprofile/nip-05 identifier
// into actual key material -- id, id sign, id delegate, and miner mine.
package keyresolve

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/ohstr/ncli/cli/common"
	"github.com/ohstr/ncli/client"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/term"
)

// ClassifyIdentifierError picks InvalidInputError (a malformed npub/nsec/
// hex/nprofile string) or NetworkError (a nip-05 "name@domain" lookup that
// failed to resolve, e.g. DNS/HTTP) for a client.ResolveIdentifier failure
// -- both funnel into one error return without a distinguishable type, and
// a "name@domain"-shaped identifier's failure is overwhelmingly a network
// problem, not a malformed-string one.
func ClassifyIdentifierError(cmd *cobra.Command, identifier string, err error) error {
	input := common.RedactSecretInput(identifier)
	if strings.Contains(identifier, "@") {
		return common.NetworkError(cmd, input, err)
	}
	// No identifier shape and no such vault label: the referenced entry
	// doesn't exist (AGENTS.md's not_found), not a malformed value.
	if errors.Is(err, client.ErrUnknownIdentifier) {
		return common.NotFoundError(cmd, input, err)
	}
	return common.InvalidInputError(cmd, input, err)
}

// Pubkey resolves a person -- vault label, npub, hex, nprofile, nip-05 or
// nsec -- to a lowercase hex pubkey. A nip-05 is fetched over HTTPS.
func Pubkey(cmd *cobra.Command, value string) (string, error) {
	resolved, err := client.ResolveIdentifier(value)
	if err != nil {
		return "", ClassifyIdentifierError(cmd, value, err)
	}
	return strings.ToLower(resolved.PubKeyHex), nil
}

// PubkeyArg is Pubkey for an input that used to take only hex or npub: a
// value that names no one stays invalid_input, as it was, rather than
// not_found.
func PubkeyArg(cmd *cobra.Command, value string) (string, error) {
	resolved, err := client.ResolveIdentifier(value)
	if errors.Is(err, client.ErrUnknownIdentifier) {
		return "", common.InvalidInputError(cmd, common.RedactSecretInput(value), err)
	}
	if err != nil {
		return "", ClassifyIdentifierError(cmd, value, err)
	}
	return strings.ToLower(resolved.PubKeyHex), nil
}

// VaultError classifies a vault unlock/create failure: a vault key gone
// missing (identities saved, key lost) is not_found; anything else -- a
// wrong password -- is auth.
func VaultError(cmd *cobra.Command, err error) error {
	if errors.Is(err, client.ErrVaultKeyMissing) {
		return common.NotFoundError(cmd, "", err)
	}
	return common.AuthError(cmd, err)
}

// ResolveVaultPassword sources the vault password from NCLI_VAULT_PASSWORD
// if set (a universal override, in any mode), otherwise errors in JSON
// mode (never prompts -- an agent driving this over a pipe has no TTY to
// prompt), otherwise prompts interactively with promptText.
func ResolveVaultPassword(jsonMode bool, promptText string) (string, error) {
	if pw := viper.GetString("vault.password"); pw != "" {
		return pw, nil
	}
	if jsonMode {
		return "", errors.New("vault password required; set NCLI_VAULT_PASSWORD")
	}
	return PromptPassword(promptText)
}

// ErrNoTerminal is returned when a secret must be read interactively but
// there is no terminal to read it from: neither the controlling terminal
// (/dev/tty on Unix, CONIN$ on Windows) nor stdin is one. Its message names
// the non-interactive paths instead of surfacing the cryptic "inappropriate
// ioctl for device" a raw termios read on a pipe returns (issue #205).
var ErrNoTerminal = errors.New("no terminal available for the password prompt; " +
	"set NCLI_VAULT_PASSWORD, or sign from a file with `ncli id sign -e <file>`")

// PromptPassword prints prompt to stdout and reads a password with echo
// disabled. The read comes from the controlling terminal, not fd 0, so it
// still prompts when stdin is a pipe feeding the command its input (e.g.
// `ncli event new … | ncli publish -e - --signer <label>`) -- the same way
// ssh-keygen/sudo read a passphrase. Only reached when --json is unset and
// NCLI_VAULT_PASSWORD is unset, i.e. the deliberately-interactive path.
func PromptPassword(prompt string) (string, error) {
	fmt.Print(prompt)
	pw, err := ReadSecretTTY()
	fmt.Println()
	if err != nil {
		return "", err
	}
	return pw, nil
}

// ReadSecretTTY reads one line with terminal echo disabled from the
// controlling terminal rather than fd 0, and returns it. The caller prints
// its own prompt first (to stdout or stderr); ReadSecretTTY prints nothing.
// When the controlling terminal can't be opened it falls back to fd 0 only
// if fd 0 is itself a terminal, and otherwise returns ErrNoTerminal rather
// than letting a termios ioctl fail cryptically on a piped stdin.
func ReadSecretTTY() (string, error) {
	return readSecretTTY(openTTY, readPasswordFd, stdinIsTerminal)
}

// readSecretTTY is ReadSecretTTY's dependency-injected core, so the branch
// selection can be unit-tested without a real terminal: openTTY opens the
// controlling terminal, readFd reads an echo-disabled line from a terminal
// fd, and stdinIsTerminal reports whether fd 0 is a terminal.
func readSecretTTY(openTTY func() (*os.File, error), readFd func(int) (string, error), stdinIsTerminal func() bool) (string, error) {
	if tty, err := openTTY(); err == nil {
		defer func() { _ = tty.Close() }()
		return readFd(int(tty.Fd()))
	}
	if stdinIsTerminal() {
		return readFd(int(os.Stdin.Fd()))
	}
	return "", ErrNoTerminal
}

func readPasswordFd(fd int) (string, error) {
	b, err := term.ReadPassword(fd)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func stdinIsTerminal() bool {
	return term.IsTerminal(int(os.Stdin.Fd()))
}

// UnlockOrCreateVault returns the vault's own decrypted private key --
// unlocking the existing vault (NCLI_VAULT_PASSWORD, or an interactive
// prompt), or creating a brand-new one first (set-and-confirm prompt, or
// NCLI_VAULT_PASSWORD again) if none exists yet. Shared by every command
// that saves a freshly generated identity into the vault as a step of its
// own flow, rather than "id"'s top-level interactive save (id.go's
// saveIdentity narrates around this same exists/unlock/create sequence
// itself).
func UnlockOrCreateVault(cmd *cobra.Command, jsonMode bool) (string, error) {
	exists, err := client.VaultExists()
	if err != nil {
		return "", err
	}
	if !exists {
		password, err := ResolveNewVaultPassword(jsonMode)
		if err != nil {
			return "", common.UsageError(cmd, err)
		}
		_, privHex, err := client.CreateVaultIdentity(password)
		if err != nil {
			if errors.Is(err, client.ErrVaultKeyMissing) {
				return "", common.NotFoundError(cmd, "", err)
			}
			return "", fmt.Errorf("failed to create vault: %w", err)
		}
		return privHex, nil
	}

	password, err := ResolveVaultPassword(jsonMode, "Vault password: ")
	if err != nil {
		return "", common.UsageError(cmd, err)
	}
	privHex, err := client.UnlockVaultIdentity(password)
	if err != nil {
		return "", VaultError(cmd, err)
	}
	return privHex, nil
}

// ResolveNewVaultPassword sources the password to protect a brand-new
// vault identity. When it comes from NCLI_VAULT_PASSWORD, the
// confirm-by-retyping step is skipped -- there's no risk of a mistyped
// confirmation when the value came from one authoritative source rather
// than two rounds of human typing.
func ResolveNewVaultPassword(jsonMode bool) (string, error) {
	if pw := viper.GetString("vault.password"); pw != "" {
		return pw, nil
	}
	if jsonMode {
		return "", errors.New("vault password required; set NCLI_VAULT_PASSWORD")
	}
	return promptNewPassword()
}

func promptNewPassword() (string, error) {
	pw, err := PromptPassword("Set a vault password: ")
	if err != nil {
		return "", err
	}
	if pw == "" {
		return "", errors.New("password must not be empty")
	}
	confirm, err := PromptPassword("Confirm vault password: ")
	if err != nil {
		return "", err
	}
	if pw != confirm {
		return "", errors.New("passwords did not match")
	}
	return pw, nil
}

// ResolveIdentity picks a signing identity by precedence -- identityFlag
// (if set), then configKey's viper value, then the vault's sole saved
// entry if exactly one exists -- and resolves it down to a private key
// hex, erroring if no identity can be determined at all or if the vault
// has multiple entries with none chosen. Use this where the command
// cannot proceed without exactly one identity (e.g. "huddle join", which
// has nothing to authenticate with otherwise); for a command where
// authenticating is optional, use ResolveIdentityOptional instead.
func ResolveIdentity(cmd *cobra.Command, identityFlag, configKey string) (string, error) {
	identity := identityFlag
	if identity == "" {
		identity = viper.GetString(configKey)
	}

	if identity == "" {
		entries, err := client.LoadVaultEntries()
		if err != nil {
			return "", common.RuntimeError(cmd, err)
		}
		switch len(entries) {
		case 0:
			return "", common.InvocationError(cmd, fmt.Errorf("--identity is required (or set %s): no vault identity to fall back to", envVarHint(configKey)))
		case 1:
			identity = entries[0].Label
		default:
			return "", common.InvocationError(cmd, fmt.Errorf("--identity is required (or set %s): the vault has %d saved identities, none chosen by default", envVarHint(configKey), len(entries)))
		}
	}

	return resolveNamedIdentity(cmd, identity, false)
}

// ResolveIdentityOptional is ResolveIdentity's opportunistic counterpart,
// for commands where authenticating is a bonus, not a requirement --
// public content is unaffected either way, and the only cost of skipping
// it is missing content gated behind NIP-42. It returns "", nil (not an
// error) in exactly the cases ResolveIdentity would otherwise refuse to
// guess or fail to resolve: no flag/config value set and the vault has
// zero or more than one entry, or (with jsonMode true) a sole vault entry
// that turns out to need an interactive password prompt. An identity that
// *was* explicitly named by flag or config still fails loudly if it can't
// be resolved -- silently dropping a typo'd --identity would be worse
// than erroring on one, and is exactly the "no events found" ambiguity
// this exists to avoid.
func ResolveIdentityOptional(cmd *cobra.Command, identityFlag, configKey string, jsonMode bool) (string, error) {
	identity := identityFlag
	explicit := identity != ""
	if identity == "" {
		identity = viper.GetString(configKey)
		explicit = identity != ""
	}

	if identity == "" {
		entries, err := client.LoadVaultEntries()
		if err != nil {
			return "", common.RuntimeError(cmd, err)
		}
		if len(entries) != 1 {
			return "", nil
		}
		identity = entries[0].Label
	}

	privKeyHex, err := resolveNamedIdentity(cmd, identity, jsonMode)
	if err != nil && !explicit {
		return "", nil
	}
	return privKeyHex, err
}

// envVarHint turns a viper dotted config key (e.g. "huddle.identity") into
// the NCLI_-prefixed, underscore-joined env var that sets it (e.g.
// "NCLI_HUDDLE_IDENTITY"), matching root.go's SetEnvPrefix("NCLI") +
// SetEnvKeyReplacer(".", "_") -- so the hint in an error message can't
// drift out of sync with the actual env var name.
func envVarHint(configKey string) string {
	return "NCLI_" + strings.ToUpper(strings.ReplaceAll(configKey, ".", "_"))
}

// resolveNamedIdentity turns an already-chosen identifier (vault label,
// nsec, npub, hex, nprofile, or nip-05) into its private key, rejecting a
// pubkey-only identity -- authenticating means signing, so there is
// nothing useful ResolveIdentity/ResolveIdentityOptional can return for
// one.
func resolveNamedIdentity(cmd *cobra.Command, identity string, jsonMode bool) (string, error) {
	resolved, err := client.ResolveIdentifier(identity)
	if err != nil {
		return "", ClassifyIdentifierError(cmd, identity, err)
	}

	privKeyHex, err := ResolveSigningKey(cmd, jsonMode, resolved)
	if err != nil {
		return "", err
	}
	if privKeyHex == "" {
		return "", common.AuthError(cmd, fmt.Errorf("identity %q has no private key available", common.RedactSecretInput(identity)))
	}
	return privKeyHex, nil
}

// ResolveSigningKey returns the private key behind resolved -- directly,
// for an nsec identity (client.ResolveIdentifier already decoded it), or
// via the vault, for a saved vault label (ResolveVaultPassword ->
// client.UnlockVaultIdentity -> client.FindVaultEntry ->
// client.DecryptVaultEntry, the same sequence "id --reveal" uses). Returns
// "", nil (not an error) for a pubkey-only identity (npub/hex/nprofile/
// nip-05) that has no private key at all -- callers that tolerate an
// unsigned/pubkey-only result (like "miner mine --identity") treat "" as
// "nothing to sign with, carry on"; callers that require a private key
// (like "id sign", "id delegate") turn "" into a hard failure themselves.
func ResolveSigningKey(cmd *cobra.Command, jsonMode bool, resolved *client.IdentityInspection) (string, error) {
	if resolved.PrivKeyHex != "" {
		return resolved.PrivKeyHex, nil
	}
	if !resolved.InVault {
		return "", nil
	}

	password, err := ResolveVaultPassword(jsonMode, "Vault password: ")
	if err != nil {
		return "", common.UsageError(cmd, err)
	}
	vaultPrivKeyHex, err := client.UnlockVaultIdentity(password)
	if err != nil {
		return "", VaultError(cmd, err)
	}
	entry, found, err := client.FindVaultEntry(resolved.Npub)
	if err != nil {
		return "", common.RuntimeError(cmd, err)
	}
	if !found {
		return "", common.NotFoundError(cmd, resolved.Npub, fmt.Errorf("vault entry disappeared during signing"))
	}
	privKeyHex, err := client.DecryptVaultEntry(vaultPrivKeyHex, *entry)
	if err != nil {
		return "", common.RuntimeError(cmd, err)
	}
	return privKeyHex, nil
}
