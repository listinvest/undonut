package undonut

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

// Load unpacks Donut shellcode
func Load(shellcode io.Reader) (*Instance, error) {
	var opcode byte
	err := binary.Read(shellcode, binary.LittleEndian, &opcode)
	if err != nil {
		return nil, fmt.Errorf("Unable to read first byte: %w", err)
	}

	if opcode != 0xE8 {
		return nil, fmt.Errorf("First byte isn't a call")
	}

	var instanceSize uint32
	err = binary.Read(shellcode, binary.LittleEndian, &instanceSize)
	if err != nil {
		return nil, fmt.Errorf("Unable to read instanceSize: %w", err)
	}

	var instanceH instanceHeader
	err = binary.Read(shellcode, binary.LittleEndian, &instanceH)
	if err != nil {
		return nil, fmt.Errorf("Unable to read instanceHeader: %w", err)
	}

	if instanceSize != instanceH.Size {
		return nil, fmt.Errorf("Failed processing shellcode")
	}

	bodyB := make([]byte, (instanceH.Size - uint32(binary.Size(instanceHeader{}))))
	err = binary.Read(shellcode, binary.LittleEndian, bodyB)
	if err != nil {
		return nil, fmt.Errorf("Unable to read instanceBody: %w", err)
	}

	decryptedB, _, err := DonutEncrypt(instanceH.Crypt.MasterKey, instanceH.Crypt.Nonce, bodyB)
	if err != nil {
		return nil, fmt.Errorf("Error decrypting body: %w", err)
	}

	var instanceB instanceBody
	dreader := bytes.NewReader(decryptedB)
	err = binary.Read(dreader, binary.LittleEndian, &instanceB)
	if err != nil {
		return nil, fmt.Errorf("Unable to read instance offset: %w", err)
	}

	return &Instance{instanceHeader: instanceH, instanceBody: instanceB, Data: dreader}, nil
}
