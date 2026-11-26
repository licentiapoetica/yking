package main

import (
	"fmt"
	"os"
	"os/user"
	"strings"

	"github.com/licentiapoetica/yking/internal/doctor"
	"github.com/licentiapoetica/yking/internal/ykman"
)

func cmdDoctor(c *ykman.Client, krPath string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	u, err := user.Current()
	if err != nil {
		return err
	}
	self, _ := os.Executable()
	in, err := doctor.Gather(doctor.Options{KeyringPath: krPath, Home: home, User: u.Username, Client: c, Self: self})
	if err != nil {
		return err
	}
	fmt.Printf("%-13s %-12s %-4s %-5s %-11s %s\n", "KEY", "ROLE", "PAM", "SSH", "LAST TEST", "SERVERS")
	for _, r := range doctor.Coverage(in) {
		p, last := "no", "never"
		if r.PAM {
			p = "yes"
		}
		if !r.LastTest.IsZero() {
			last = r.LastTest.Local().Format("2006-01-02")
		}
		fmt.Printf("%-13s %-12s %-4s %-5d %-11s %s\n", r.Label, r.Role, p, r.SSHKeys, last, strings.Join(r.Hosts, ", "))
	}
	fmt.Println()
	f := doctor.Run(in)
	for _, x := range f {
		fmt.Printf("%-5s %-6s %s\n", x.Severity, x.Area, x.Message)
		if x.Fix != "" {
			fmt.Printf("             → %s\n", x.Fix)
		}
	}
	if doctor.Worst(f) == doctor.Error {
		os.Exit(1)
	}
	return nil
}
