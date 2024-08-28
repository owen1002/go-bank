package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
)

type APIServer struct {
	listenAddress string
	store         Storage
}

func NewAPIServer(listenAddress string, store Storage) *APIServer {
	return &APIServer{
		listenAddress: listenAddress,
		store:         store,
	}
}

func (s *APIServer) Run() {
	router := mux.NewRouter()
	router.HandleFunc("/account", makeHttpHandleFunc(s.handleAccount))
	router.HandleFunc("/account/{id}", withJWTAuth(makeHttpHandleFunc(s.handleAccountByID)))
	router.HandleFunc("/transfer", makeHttpHandleFunc(s.handleTransfer))
	router.HandleFunc("/login", makeHttpHandleFunc(s.login))

	http.ListenAndServe(s.listenAddress, router)
}

func (s *APIServer) handleAccount(writer http.ResponseWriter, req *http.Request) error {
	switch req.Method {
	case "GET":
		return s.handleGetAccounts(writer, req)
	case "POST":
		return s.handleCreateAccount(writer, req)
	default:
		return fmt.Errorf("method not allowed %s", req.Method)
	}
}

func (s *APIServer) handleAccountByID(writer http.ResponseWriter, req *http.Request) error {
	switch req.Method {
	case "GET":
		return s.handleGetAccountByID(writer, req)
	case "DELETE":
		return s.handleDeleteAccount(writer, req)
	default:
		return fmt.Errorf("method not allowed %s", req.Method)
	}
}

func (s *APIServer) handleGetAccounts(writer http.ResponseWriter, req *http.Request) error {
	accounts, err := s.store.GetAccounts()
	if err != nil {
		return err
	}

	// return DB.get
	return WriteJSON(writer, http.StatusOK, accounts)
}

func (s *APIServer) handleGetAccountByID(writer http.ResponseWriter, req *http.Request) error {
	id, err := getAccountIdFromReq(req)
	if err != nil {
		return err
	}

	account, err := s.store.GetAccountByID(id)

	if err != nil {
		return err
	}
	// return DB.get
	return WriteJSON(writer, http.StatusOK, account)
}

func (s *APIServer) handleCreateAccount(writer http.ResponseWriter, req *http.Request) error {
	createAccountReq := CreateAccountRequest{}
	if err := json.NewDecoder(req.Body).Decode(&createAccountReq); err != nil {
		return err
	}
	defer req.Body.Close()

	account, err := NewAccount(createAccountReq.FirstName, createAccountReq.LastName, createAccountReq.Password)
	if err != nil {
		return err
	}
	if err := s.store.CreateAccount(account); err != nil {
		return err
	}

	return WriteJSON(writer, http.StatusOK, "created")
}

func (s *APIServer) handleDeleteAccount(writer http.ResponseWriter, req *http.Request) error {
	id, err := getAccountIdFromReq(req)
	if err != nil {
		return err
	}

	if err := s.store.DeleteAccount(id); err != nil {
		return err
	}
	return WriteJSON(writer, http.StatusOK, map[string]int{"deleted ": id})
}

func (s *APIServer) handleTransfer(writer http.ResponseWriter, req *http.Request) error {
	transferReq := TransferRequest{}
	if err := json.NewDecoder(req.Body).Decode(&transferReq); err != nil {
		return err
	}
	defer req.Body.Close()

	return WriteJSON(writer, http.StatusOK, transferReq)
}

func (s *APIServer) login(writer http.ResponseWriter, req *http.Request) error {
	loginReq := LoginRequest{}
	if err := json.NewDecoder(req.Body).Decode(&loginReq); err != nil {
		return err
	}

	account, err := s.store.GetAccountByAccountNumber(loginReq.Number)

	if err != nil {
		return err
	}

	if err := bcrypt.CompareHashAndPassword([]byte(account.EncryptedPassword), []byte(loginReq.Password)); err != nil {
		return WriteJSON(writer, http.StatusForbidden, "Password mismatch")
	}

	tokenString, err := createJWT(account)
	if err != nil {
		return err
	}
	return WriteJSON(writer, http.StatusOK, tokenString)

}

func WriteJSON(writer http.ResponseWriter, status int, v any) error {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	return json.NewEncoder(writer).Encode(v)
}

func withJWTAuth(handlerFunc http.HandlerFunc) http.HandlerFunc {
	return func(writer http.ResponseWriter, req *http.Request) {
		jwtString := req.Header.Get("x-jwt-token")
		token, err := validateJWT(jwtString)
		if err != nil {
			WriteJSON(writer, http.StatusForbidden, ApiError{Error: "access denied"})
			return
		}
		if !token.Valid {
			WriteJSON(writer, http.StatusForbidden, ApiError{Error: "access denied"})
			return
		}
		idFromReq, err := getAccountIdFromReq(req)
		if err != nil {
			WriteJSON(writer, http.StatusForbidden, ApiError{Error: "access denied"})
			return
		}

		claims := token.Claims.(jwt.MapClaims)
		idFromClaims := claims["accountID"]
		// omg I need custom claim here actually fmt.Println(reflect.TypeOf(idFromClaims))
		if idFromReq != int(idFromClaims.(float64)) {
			WriteJSON(writer, http.StatusForbidden, ApiError{Error: "access denied"})
			return
		}

		handlerFunc(writer, req)
	}
}

func createJWT(account *Account) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"accountID":     account.ID,
		"accountNumber": account.Number,
		"nbf":           time.Date(2015, 10, 10, 12, 0, 0, 0, time.UTC).Unix(),
	})

	secret := os.Getenv("JWT_SECRET")
	// Sign and get the complete encoded token as a string using the secret
	return token.SignedString([]byte(secret))
}

func validateJWT(tokenString string) (*jwt.Token, error) {
	secret := os.Getenv("JWT_SECRET")
	// Parse takes the token string and a function for looking up the key. The latter is especially
	// useful if you use multiple keys for your application.  The standard is to use 'kid' in the
	// head of the token to identify which key to use, but the parsed token (head and claims) is provided
	// to the callback, providing flexibility.
	return jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		// hmacSampleSecret is a []byte containing your secret, e.g. []byte("my_secret_key")
		return []byte(secret), nil
	})
}

type apiFunc func(http.ResponseWriter, *http.Request) error

type ApiError struct {
	Error string `json:"error"`
}

func makeHttpHandleFunc(f apiFunc) http.HandlerFunc {
	return func(writer http.ResponseWriter, req *http.Request) {
		if err := f(writer, req); err != nil {
			WriteJSON(writer, http.StatusBadRequest, ApiError{Error: err.Error()})
		}
	}
}

func getAccountIdFromReq(req *http.Request) (int, error) {
	idStr := mux.Vars(req)["id"]
	id, err := strconv.Atoi(idStr)
	if err != nil {
		return id, fmt.Errorf("invalid id %s", idStr)
	}
	return id, nil
}

func getAccountNumberFromReq(req *http.Request) (int, error) {
	accStr := mux.Vars(req)["accountNumber"]
	accountNumber, err := strconv.Atoi(accStr)
	if err != nil {
		return accountNumber, fmt.Errorf("invalid account number %s", accStr)
	}
	return accountNumber, nil
}
