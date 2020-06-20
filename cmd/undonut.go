package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	undonut "github.com/kulinacs/undonut/pkg"
)

func main() {
	var shellcode = flag.String("shellcode", "", "shellcode to undonut")
	var recover = flag.String("recover", "", "path to write the recovered file to")

	flag.Parse()

	if shellcode == nil || *shellcode == "" {
		fmt.Printf("No shellcode file specified - see usage with -h\n")
		return
	}

	fd, err := os.Open(*shellcode)
	if err != nil {
		fmt.Printf("Unable to open file: %s\n", err.Error())
		return
	}

	inst, err := undonut.Load(fd)
	if err != nil {
		fmt.Printf("Failed to load donut: %s\n", err.Error())
		return
	}

	fmt.Println(inst)

	if recover != nil && *recover != "" {

		fmt.Printf("Extracting original payload to %v...\n", *recover)

		rec, err := os.Create(*recover)
		if err != nil {
			fmt.Printf("Unable to create file: %s\n", err.Error())
			return
		}
		defer rec.Close()

		io.Copy(rec, inst.Data)
	}
}
