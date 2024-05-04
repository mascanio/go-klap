package main

import (
	"log"
	"os"
)

func main() {
	user := os.Getenv("user")
	pass := os.Getenv("pass")
	k := New("192.168.4.103", "80", user, pass)
	if err := k.Handshake(); err != nil {
		log.Fatalln(err)
	}
}
