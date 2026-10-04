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
	default:
		return fmt.Errorf("open %s manually", u)
	}
}
