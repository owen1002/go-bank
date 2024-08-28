package main

import (
	"flag"
	"fmt"
	"log"
)

func seedAccount(s Storage, fname, lname, pw string) {
	acc, err := NewAccount(fname, lname, pw)
	if err != nil {
		log.Fatal("Failed to seed account")
	}
	if err := s.CreateAccount(acc); err != nil {
		log.Fatal("Failed to seed account")
	}
	log.Printf("seed account number : %d", acc.Number)
}

func seedAccounts(s Storage) {
	seedAccount(s, "Owen", "siu", "ggwpmypw")
}

func main() {
	// ./bin/gobank --seed
	seed := flag.Bool("seed", false, "seed db")
	flag.Parse()

	store, err := NewPostgresStore()
	server := NewAPIServer(":5000", store)

	if err != nil {
		log.Fatal(err)
	}

	if err := store.init(); err != nil {
		log.Fatal(err)
	}

	if *seed {
		seedAccounts(store)
	}
	fmt.Println("Server is running on PORT 5000")
	server.Run()
}
