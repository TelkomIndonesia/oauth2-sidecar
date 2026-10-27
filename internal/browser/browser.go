package browser

import (
	"fmt"
	"os/exec"
	"runtime"
)

func OpenURL(u string) error {
	switch runtime.GOOS {
	case "darwin":
		return exec.Command("open", u).Start()
	case "linux":
		return exec.Command("xdg-open", u).Start()
	case "windows":
		// Not "cmd /c start": cmd cuts the URL at &.
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", u).Start()
	default:
		return fmt.Errorf("open %s manually", u)
	}
}
