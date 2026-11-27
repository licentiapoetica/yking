package luks

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// GRUB's own 10_linux entry assumes a separate initramfs. On a UKI system
// it boots the kernel with only the microcode image ("VFS: Unable to mount
// root fs on unknown-block(0,0)"). So before and after a boot change yking
// checks what GRUB's DEFAULT entry actually boots.

// FirstEntry returns the body of grub.cfg's first top-level menuentry.
func FirstEntry(cfg string) (string, error) {
	lines := strings.Split(cfg, "\n")
	for i, l := range lines {
		if !strings.HasPrefix(l, "menuentry ") {
			continue
		}
		for j := i + 1; j < len(lines); j++ {
			if strings.HasPrefix(lines[j], "}") {
				return strings.Join(lines[i:j+1], "\n"), nil
			}
		}
		return "", errors.New("grub.cfg: first menuentry is not closed")
	}
	return "", errors.New("grub.cfg has no menuentry")
}

// DefaultBoots checks that GRUB's default entry boots the expected image:
// with uki set, it chainloads that UKI (path on the ESP); otherwise it loads
// /initramfs-linux.img.
func DefaultBoots(cfg, grubDefault, uki string) error {
	if d := strings.Trim(grubDefault, `"'`); d != "" && d != "0" {
		return fmt.Errorf("GRUB_DEFAULT=%s: yking cannot tell which entry boots; set it to 0", d)
	}
	e, err := FirstEntry(cfg)
	if err != nil {
		return err
	}
	title := strings.SplitN(e, "\n", 2)[0]
	if uki != "" {
		for _, l := range strings.Split(e, "\n") {
			if f := strings.Fields(l); len(f) == 2 && f[0] == "chainloader" && f[1] == uki {
				return nil
			}
		}
		return fmt.Errorf("GRUB's default entry (%s) does not chainload %s", strings.TrimSpace(title), uki)
	}
	for _, l := range strings.Split(e, "\n") {
		if f := strings.Fields(l); len(f) >= 2 && f[0] == "initrd" && strings.Contains(l, "/initramfs-linux.img") {
			return nil
		}
	}
	return fmt.Errorf("GRUB's default entry (%s) does not load /initramfs-linux.img", strings.TrimSpace(title))
}

func grubDefaultValue() string {
	b, _ := os.ReadFile(GrubDefault)
	for _, l := range strings.Split(string(b), "\n") {
		if m := grubVarRe.FindStringSubmatch(strings.TrimSpace(l)); m != nil && m[1] == "GRUB_DEFAULT" {
			return m[2]
		}
	}
	return ""
}

// CheckGrubWouldBoot runs grub-mkconfig into a temporary file (nothing is
// installed) and checks its default entry (root).
func CheckGrubWouldBoot(uki string) error {
	tmp, err := os.CreateTemp("", "yking-grub-*.cfg")
	if err != nil {
		return err
	}
	tmp.Close()
	defer os.Remove(tmp.Name())
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if out, err := exec.CommandContext(ctx, "grub-mkconfig", "-o", tmp.Name()).CombinedOutput(); err != nil {
		return fmt.Errorf("grub-mkconfig: %v: %s", err, lastLine(out))
	}
	cfg, err := os.ReadFile(tmp.Name())
	if err != nil {
		return err
	}
	return DefaultBoots(string(cfg), grubDefaultValue(), uki)
}

// checkGrubBoots checks the installed grub.cfg.
func checkGrubBoots(uki string) error {
	cfg, err := os.ReadFile(GrubCfg)
	if err != nil {
		return err
	}
	return DefaultBoots(string(cfg), grubDefaultValue(), uki)
}

func lastLine(b []byte) string {
	l := strings.Split(strings.TrimSpace(string(b)), "\n")
	return l[len(l)-1]
}
