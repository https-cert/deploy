package utils

import (
	"encoding/json"
	"fmt"
)

func PrintlnJson(obj any) {
	jsonBytes, _ := json.MarshalIndent(obj, "", "\t")
	fmt.Println(string(jsonBytes))
}
