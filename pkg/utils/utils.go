package utils

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
)

func PrintlnJson(obj any) {
	jsonBytes, _ := json.Marshal(obj, jsontext.WithIndent("\t"))
	fmt.Println(string(jsonBytes))
}
