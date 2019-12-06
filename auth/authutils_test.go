package authutils

import "testing"

type passwordValidationTestCase struct {
	input    string
	expected bool
	number   int
}

func Test_PasswordValidation(t *testing.T) {
	cases := []passwordValidationTestCase{
		passwordValidationTestCase{input: "test", expected: true, number: 1},
		passwordValidationTestCase{input: "test-", expected: true, number: 2},
		passwordValidationTestCase{input: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", expected: true, number: 3},
		passwordValidationTestCase{input: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", expected: false, number: 4},
		passwordValidationTestCase{input: "", expected: false, number: 5},
		passwordValidationTestCase{input: "ko", expected: false, number: 6},
		passwordValidationTestCase{input: "+++-", expected: true, number: 7},
		passwordValidationTestCase{input: ".\"'-", expected: true, number: 8},
		passwordValidationTestCase{input: "a*()_", expected: true, number: 9},
		passwordValidationTestCase{input: "!@#$%", expected: true, number: 10},
		passwordValidationTestCase{input: "ales:si", expected: false, number: 11},
	}

	for _, c := range cases {
		if c.expected != PasswordValidation(c.input) {
			t.Errorf("Expected %v for input %v [test n. %d]", c.expected, c.input, c.number)
		}
	}
}

func Test_ValidateUsername(t *testing.T) {
	cases := []passwordValidationTestCase{
		passwordValidationTestCase{input: "test", expected: true, number: 1},
		passwordValidationTestCase{input: "test-", expected: true, number: 2},
		passwordValidationTestCase{input: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", expected: true, number: 3},
		passwordValidationTestCase{input: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", expected: false, number: 4},
		passwordValidationTestCase{input: "", expected: false, number: 5},
		passwordValidationTestCase{input: "ko", expected: false, number: 6},
		passwordValidationTestCase{input: "+++-", expected: false, number: 7},
		passwordValidationTestCase{input: ".\"'-", expected: false, number: 8},
		passwordValidationTestCase{input: "a*()_", expected: false, number: 9},
		passwordValidationTestCase{input: "!@#$%", expected: false, number: 10},
		passwordValidationTestCase{input: "ales:si", expected: false, number: 11},
		passwordValidationTestCase{input: "alessio_savi", expected: true, number: 12},
		passwordValidationTestCase{input: "alessio-savi", expected: true, number: 13},
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

		basicauthTestCase{header: []byte("Basic YWxhZGRpbjpvcGVuc2VzYW1l"), name: "aladdin", pass: "opensesame", number: 1},
		basicauthTestCase{header: []byte("Basic YWxlc3NpbzpzYXZpCg=="), name: "alessio", pass: "savi", number: 2},
		basicauthTestCase{header: []byte(""), name: "", pass: "", number: 3},
		basicauthTestCase{header: []byte("Test YWxhZGRpbjpvcGVuc2VzYW1l"), name: "", pass: "", number: 4},
		basicauthTestCase{header: []byte("YWxhZGRpbjpvcGVuc2VzYW1l"), name: "", pass: "", number: 5},
		basicauthTestCase{header: []byte("Basic YWxhZGRpbjp vcGVuc2VzYW1l"), name: "", pass: "", number: 6},
	}

	for _, c := range cases {
		u, p := ParseAuthCredentialFromHeaders(c.header)
		if c.name != u && c.pass != p {
			t.Errorf("Expected %v:%v for input %v [test n. %d]", c.name, c.pass, c.header, c.number)
		}
	}
}
