package main

import (
	"database/sql"
	"fmt"

	_ "github.com/lib/pq"
)

type Storage interface {
	CreateAccount(*Account) error
	UpdateAccount(*Account) error
	DeleteAccount(int) error
	GetAccounts() ([]*Account, error)
	GetAccountByID(int) (*Account, error)
	GetAccountByAccountNumber(int) (*Account, error)
}

type PostgresStore struct {
	db *sql.DB
}

func NewPostgresStore() (*PostgresStore, error) {
	// docker run --name some-postgres -e POSTGRES_PASSWORD=gobank -p 5432:5432 -d postgres
	connStr := "user=postgres dbname=postgres password=gobank sslmode=disable"
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return nil, err
	}

	if err := db.Ping(); err != nil {
		return nil, err
	}

	return &PostgresStore{db: db}, nil
}

func (s *PostgresStore) init() error {
	return s.createAccountTable()
}

func (s *PostgresStore) createAccountTable() error {
	query := `create table if not exists account (
		id serial PRIMARY KEY,
		first_name varchar(50),
		last_name varchar(50),
		number serial,
		encrypted_password text,
		balance int,
		created_at timestamp
	)`

	_, err := s.db.Exec(query)
	return err
}

// todo: encrypted password
func (s *PostgresStore) CreateAccount(acc *Account) error {
	query := `
	insert into account (first_name, last_name, balance, encrypted_password, created_at)
	values ($1, $2, $3, $4, $5)
	`
	_, err := s.db.Exec(query, acc.FirstName, acc.LastName, acc.Balance, acc.EncryptedPassword, acc.CreatedAt)

	if err != nil {
		return err
	}

	return nil
}
func (s *PostgresStore) UpdateAccount(*Account) error {
	return nil
}
func (s *PostgresStore) DeleteAccount(id int) error {
	query := "delete from account where id = $1"
	_, err := s.db.Exec(query, id)
	return err
}

func (s *PostgresStore) GetAccounts() ([]*Account, error) {
	query := "select * from account"
	rows, err := s.db.Query(query)
	if err != nil {
		return nil, err
	}

	accounts := []*Account{}
	for rows.Next() {
		acc, err := ScanIntoAccount(rows)
		if err != nil {
			return nil, err
		}
		accounts = append(accounts, acc)
	}
	return accounts, nil
}
func (s *PostgresStore) GetAccountByAccountNumber(acctNumber int) (*Account, error) {
	query := "select * from account where number=$1"
	rows, err := s.db.Query(query, acctNumber)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		return ScanIntoAccount(rows)
	}
	return nil, fmt.Errorf("Account number %d not found", acctNumber)
}

func (s *PostgresStore) GetAccountByID(id int) (*Account, error) {
	query := "select * from account where id=$1"
	rows, err := s.db.Query(query, id)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		return ScanIntoAccount(rows)
	}
	return nil, fmt.Errorf("Account %d not found", id)
}

func ScanIntoAccount(rows *sql.Rows) (*Account, error) {
	acc := Account{}
	err := rows.Scan(
		&acc.ID,
		&acc.FirstName,
		&acc.LastName,
		&acc.Number,
		&acc.EncryptedPassword,
		&acc.Balance,
		&acc.CreatedAt)
	return &acc, err
}
