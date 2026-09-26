package main

import (
	"log"
	"os"

	"github.com/wongyiuming/root2key/internal/web"
)

func main() {
	addr := os.Getenv("ROOT2KEY_LISTEN")
	if addr == "" {
		addr = ":8080"
	}
	log.Printf("root2key listening on %s", addr)
	if err := web.ListenAndServe(addr); err != nil {
		log.Fatal(err)
	}
}
