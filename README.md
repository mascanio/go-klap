# go-klap
Go library for communicating with tapo/tplink devices using the klap protocol.

## Usage
Just instantiate a new Kalp object and call the Request method with the desired command and parameters.

```go
package main

import (
    "log"
    goklap "github.com/mascanio/go-klap"
)

func main() {
    // User and pass are the credentials for your tapo/tplink account
    k := goklap.New("192.168.4.103", "80", user, pass)
	data := "{\"method\": \"get_energy_usage\", \"params\": null}"

	r, err := k.Request("request", data)
	if err != nil {
        log.Fatal(err)
	}
    log.Println(r)
}
```

Note that the Klap object, while being reutilizable, is not thread safe. If you need to use it in a concurrent environment, you should create a new object for each goroutine.
