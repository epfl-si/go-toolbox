package token_test

import (
	"fmt"

	"github.com/epfl-si/go-toolbox/token"
)

func Example_creating() {
	t := token.New(token.CustomClaims{Sciper: "321014"})
	encoded, err := t.Sign([]byte("secret"))
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(encoded)
	// Output: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzY2lwZXIiOiIzMjEwMTQifQ.7Nf7BUmLmN2RGXwf2nr-cOwkcsCkWO2i6YgLZdItrek
}

func Example_decoding() {
	tokenString := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzY2lwZXIiOiIzMjEwMTQifQ.7Nf7BUmLmN2RGXwf2nr-cOwkcsCkWO2i6YgLZdItrek"
	decoded, err := token.Parse(tokenString, []byte("secret"))
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(decoded.JWT.Raw)
	fmt.Println(decoded.JWT.Header["alg"])
	fmt.Println(decoded.JWT.Header["typ"])
	// fmt.Printf("%+v", decoded.JWT)
	// Output:
	// eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzY2lwZXIiOiIzMjEwMTQifQ.7Nf7BUmLmN2RGXwf2nr-cOwkcsCkWO2i6YgLZdItrek
	// HS256
	// JWT
}
