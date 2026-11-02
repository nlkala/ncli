//go:build !windows

package keyresolve

import "os"

// openTTY opens the controlling terminal for an echo-disabled secret read.
// On Unix that is /dev/tty, which stays connected to the terminal even when
// stdin and stdout are redirected or piped -- the device ssh-keygen and
// sudo read a passphrase from.
func openTTY() (*os.File, error) {
	return os.OpenFile("/dev/tty", os.O_RDWR, 0)
}
