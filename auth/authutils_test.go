package authutils

import (
	"alessiosavi/AuthentiGo/datastructures"
	"testing"
)

type passwordValidationTestCase struct {
	input    string
	expected bool
	number   int
}

func Test_PasswordValidation(t *testing.T) {
	cases := []passwordValidationTestCase{
		{input: "test", expected: true, number: 1},
		{input: "test-", expected: true, number: 2},
		{input: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", expected: true, number: 3},
		{input: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", expected: false, number: 4},
		{input: "", expected: false, number: 5},
		{input: "ko", expected: false, number: 6},
		{input: "+++-", expected: true, number: 7},
		{input: ".\"'-", expected: true, number: 8},
		{input: "a*()_", expected: true, number: 9},
		{input: "!@#$%", expected: true, number: 10},
		{input: "ales:si", expected: false, number: 11},
	}

	for _, c := range cases {
		if c.expected != PasswordValidation(c.input) {
			t.Errorf("Expected %v for input %v [test n. %d]", c.expected, c.input, c.number)
		}
	}
}

func Test_ValidateUsername(t *testing.T) {
	cases := []passwordValidationTestCase{
		{input: "test", expected: true, number: 1},
		{input: "test-", expected: true, number: 2},
		{input: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", expected: true, number: 3},
		{input: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", expected: false, number: 4},
		{input: "", expected: false, number: 5},
		{input: "ko", expected: false, number: 6},
		{input: "+++-", expected: false, number: 7},
		{input: ".\"'-", expected: false, number: 8},
		{input: "a*()_", expected: false, number: 9},
		{input: "!@#$%", expected: false, number: 10},
		{input: "ales:si", expected: false, number: 11},
		{input: "alessio_savi", expected: true, number: 12},
		{input: "alessio-savi", expected: true, number: 13},
	}

	for _, c := range cases {
		if c.expected != ValidateUsername(c.input) {
			t.Errorf("Expected %v for input %v [test n. %d]", c.expected, c.input, c.number)
		}
	}
}

type basicauthTestCase struct {
	header []byte
	name   string
	pass   string
	number int
}

func Test_ParseAuthCredentialFromHeaders(t *testing.T) {
	cases := []basicauthTestCase{

		{header: []byte("Basic YWxhZGRpbjpvcGVuc2VzYW1l"), name: "aladdin", pass: "opensesame", number: 1},
		{header: []byte("Basic YWxlc3NpbzpzYXZp"), name: "alessio", pass: "savi", number: 2},
		{header: []byte(""), name: "", pass: "", number: 3},
		{header: []byte("Test YWxhZGRpbjpvcGVuc2VzYW1l"), name: "", pass: "", number: 4},
		{header: []byte("YWxhZGRpbjpvcGVuc2VzYW1l"), name: "", pass: "", number: 5},
		{header: []byte("Basic YWxhZGRpbjp vcGVuc2VzYW1l"), name: "", pass: "", number: 6},
	}

	for _, c := range cases {
		u, p := ParseAuthCredentialFromHeaders(c.header)
		if c.name != u || c.pass != p {
			t.Errorf("Expected %s:%s for input %s [test n. %d]", c.name, c.pass, c.header, c.number)
		}
	}
}

type validateMiddlewareRequestTestCase struct {
	req      datastructures.MiddlewareRequest
	expected bool
	url      string
	number   int
}

func Test_ValidateMiddlewareRequest(t *testing.T) {
	cases := []validateMiddlewareRequestTestCase{
		{req: datastructures.MiddlewareRequest{Username: "test", Token: "testtest", Service: "http://google.it/", Method: "GET", Data: "test=1&prova=2"}, expected: true, url: "http://google.it?test=1&prova=2", number: 1},
		{req: datastructures.MiddlewareRequest{Username: "test", Token: "testtest", Service: "http://google.it/", Method: "GET", Data: ""}, expected: true, url: "http://google.it/", number: 2},
		{req: datastructures.MiddlewareRequest{Username: "test", Token: "testtest", Service: "http://google.it/", Method: "", Data: "test=1&prova=2"}, expected: true, url: "http://google.it?test=1&prova=2", number: 3},
		{req: datastructures.MiddlewareRequest{Username: "test", Token: "testtest", Service: "http://google.it/", Method: "get", Data: "test=1&prova=2"}, expected: true, url: "http://google.it?test=1&prova=2", number: 4},
		{req: datastructures.MiddlewareRequest{Username: "test", Token: "testtest", Service: "http://google.it?test2=1", Method: "get", Data: "test3=1&prova=2"}, expected: true, url: "http://google.it?test2=1&test3=1&prova=2", number: 5},
		{req: datastructures.MiddlewareRequest{Username: "test", Token: "testtest", Service: "http://google.it", Method: "GET", Data: "test=1&prova=2"}, expected: true, url: "http://google.it?test=1&prova=2", number: 6},
		{req: datastructures.MiddlewareRequest{Username: "test", Token: "testtest", Service: "http://google.it", Method: "GET", Data: ""}, expected: true, url: "http://google.it", number: 7},
		{req: datastructures.MiddlewareRequest{Username: "test", Token: "testtest", Service: "http://google.it", Method: "", Data: "test=1&prova=2"}, expected: true, url: "http://google.it?test=1&prova=2", number: 8},
		{req: datastructures.MiddlewareRequest{Username: "test", Token: "testtest", Service: "http://google.it", Method: "get", Data: "test=1&prova=2"}, expected: true, url: "http://google.it?test=1&prova=2", number: 9},
	}

	for _, c := range cases {
		expected := ValidateMiddlewareRequest(&c.req)
		// t.Log("Expected: " + c.url)
		// t.Log("Recived: " + c.req.Service)
		if expected != c.expected || c.url != c.req.Service {
			t.Errorf("Expected %v---%v [test n. %d]", c.url, c.req.Service, c.number)
		}
	}

}
