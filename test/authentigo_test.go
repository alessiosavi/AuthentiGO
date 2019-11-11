package authentigo

import (
	"alessiosavi/AuthentiGo/datastructures"
	commonutils "alessiosavi/AuthentiGo/utils/common"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"path"
	"strings"
	"testing"
)

type Data struct {
	netdata TestDataNet
}
type TestDataNet struct {
	url  string
	port string
}

func initNetData() Data {
	data := Data{}
	data.netdata.url = "127.0.0.1"
	data.netdata.port = "11001"
	return data
}

func generateTestData(data Data, functionality string, https bool) []string {
	endpoint := []string{"/auth/login", "/auth/register", "/auth/verify"}
	username := []string{"alessio", "alessio1", "alessio2", "alessio3"}
	password := []string{"alessio", "alessio1", "alessio2", "alessio3"}
	var protocol []string
	if https {
		protocol = []string{"https"}
	} else {
		protocol = []string{"http"}

	}

	if strings.Compare(functionality, "login") == 0 {
		return generateOKLoginData(protocol, data.netdata.url, data.netdata.port, endpoint[0], "user", "pass", username, password)
	} else if strings.Compare(functionality, "register") == 0 {
		return generateOKLoginData(protocol, data.netdata.url, data.netdata.port, endpoint[1], "user", "pass", username, password)
	}
	return nil

}

func generateOKLoginData(protocols []string, url, port, endpoint, userKey, pswKey string, usernames, passwords []string) []string {
	var loginOKData []string
	for _, protocol := range protocols {
		if len(usernames) == len(passwords) {
			for i := 0; i < len(usernames) && i < len(passwords); i++ {
				// Create postargs with valid credentials
				postargs := userKey + "=" + usernames[i] + "&" + pswKey + "=" + passwords[i]
				API := protocol + "://" + url + ":" + path.Join(port, endpoint) + "?" + postargs
				//fmt.Println("MakeRequest | URL: ", API)
				loginOKData = append(loginOKData, API)
			}
		} else {
			fmt.Println("generateOKLoginData | passwords and usernames size mismatch")
		}
	}
	fmt.Println(loginOKData)
	return loginOKData
}
func generateLoginData(protocols []string, url, port, endpoint, userKey, pswKey string, usernames, passwords []string) []string {
	var loginData []string
	for _, protocol := range protocols {
		for _, username := range usernames {
			for _, passwords := range passwords {
				postargs := userKey + "=" + username + "&" + pswKey + "=" + passwords
				API := protocol + "://" + url + ":" + path.Join(port, endpoint) + "?" + postargs
				//fmt.Println("MakeRequest | URL: ", API)
				loginData = append(loginData, API)
			}
		}
	}
	fmt.Println(loginData)
	return loginData
}

func MakeRequest(URL string) string {
	fmt.Println("MakeRequest | URL: ", URL)
	resp, err := http.Get(URL)
	if err != nil {
		fmt.Println(err)
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)
	}
	//fmt.Println(string(body))
	return string(body)
}

func TestRegister(t *testing.T) {
	data := initNetData()
	register_test := generateTestData(data, "register", false)
	var response []string
	// Execute GET request using the username and password provided by initNetData
	for i := range register_test {
		response = append(response, MakeRequest(register_test[i]))
	}

	for i := 0; i < len(response); i++ {
		if !verifyLoginResponse(response[i]) {
			t.Log("Error on response ", i, " | Resp: ", response[i])
			t.Fail()
		} else {
			t.Log("Success on response ", i, " | Resp: ", response[i])
		}
	}
}

func TestLogin(t *testing.T) {
	data := initNetData()
	username_test := generateTestData(data, "login", false)
	var response []string
	// Execute GET request using the username and password provided by initNetData
	for i := range username_test {
		response = append(response, MakeRequest(username_test[i]))
	}

	for i := 0; i < len(response); i++ {
		if !verifyLoginResponse(response[i]) {
			t.Log("Error on response ", i, " | Resp: ", response[i])
			t.Fail()
		} else {
			t.Log("Success on response ", i, " | Resp: ", response[i])
		}
	}
}

// TestOK is delegated to unmarshall the json string and verify if the field in input contains the "correct" given data
func verifyLoginResponse(jsonData string) bool {
	var response datastructures.Response
	err := json.Unmarshal([]byte(jsonData), &response)
	commonutils.Check(err, "verifyLoginResponse")
	return response.Status
}
