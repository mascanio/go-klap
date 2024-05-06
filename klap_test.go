package goklap_test

import (
	"encoding/json"
	"os"
	"testing"

	goklap "github.com/mascanio/go-klap"
)

type responseResult struct {
	Current_power int
}

type response struct {
	Result     responseResult
	Error_code int
}

func TestKlap(t *testing.T) {
	user := os.Getenv("user")
	pass := os.Getenv("pass")
	if user == "" || pass == "" {
		t.Error("Env variables not set")
		t.FailNow()
	}
	k := goklap.New("192.168.4.103", "80", user, pass)
	data := "{\"method\": \"get_energy_usage\", \"params\": null}"

	r, err := k.Request("request", data, nil)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	var responseParsed response
	err = json.Unmarshal(r, &responseParsed)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
}
