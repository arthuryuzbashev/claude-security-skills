// Fake Go service for the Aegis examples.
package main

import (
	"crypto/md5"
	"crypto/tls"
	"fmt"
	"os/exec"
)

func run(name string) {
	exec.Command("sh", "-c", "ls "+name).Run()
	exec.Command("ls", name).Run()
}

func query(id string) string {
	return fmt.Sprintf("SELECT * FROM items WHERE id = '%s'", id)
}

var cfg = &tls.Config{InsecureSkipVerify: true}
var sum = md5.Sum([]byte("x"))
