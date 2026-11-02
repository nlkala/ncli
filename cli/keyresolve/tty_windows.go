//go:build windows

package keyresolve

import "os"

// openTTY opens the Windows console input buffer (CONIN$), the equivalent of
// Unix's /dev/tty: it stays connected to the console even when stdin is a
// pipe. os.OpenFile maps "CONIN$" to CreateFile with
// GENERIC_READ|GENERIC_WRITE and OPEN_EXISTING, which is what it needs.
func openTTY() (*os.File, error) {
	return os.OpenFile("CONIN$", os.O_RDWR, 0)
}
