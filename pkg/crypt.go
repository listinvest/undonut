/**
  BSD 3-Clause License

  Copyright (c) 2020, kulinacs, Go Adaptation.
  Copyright (c) 2019, TheWover, Odzhan. All rights reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are met:

  * Redistributions of source code must retain the above copyright notice, this
    list of conditions and the following disclaimer.

  * Redistributions in binary form must reproduce the above copyright notice,
    this list of conditions and the following disclaimer in the documentation
    and/or other materials provided with the distribution.

  * Neither the name of the copyright holder nor the names of its
    contributors may be used to endorse or promote products derived from
    this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
  DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
  CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
  OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
package undonut

import (
	"bytes"
	"encoding/binary"
)

func ROTR32(v uint32, n byte) uint32 {
	return (v >> n) | (v << (32 - (n)))
}

// fromBytes converts a byte slice to uint32 slice for use in the encryption function
func fromBytes(byts [16]byte) ([4]uint32, error) {
	ints := [4]uint32{}
	for i := range ints {
		buf := bytes.NewReader(byts[i*4:])
		err := binary.Read(buf, binary.LittleEndian, &ints[i])
		if err != nil {
			return ints, err
		}
	}
	return ints, nil
}

// fromBytes converts a uint32 slice to a byte slice for returning from the encryption function
func fromUints(uints [4]uint32) ([16]byte, error) {
	var byts [16]byte
	buf := new(bytes.Buffer)
	for _, val := range uints {
		err := binary.Write(buf, binary.LittleEndian, val)
		if err != nil {
			return byts, err
		}
	}
	copy(byts[:], buf.Bytes())
	return byts, nil
}

func Chaskey(masterKey, value [16]byte) ([16]byte, error) {
	mk, err := fromBytes(masterKey)
	if err != nil {
		return [16]byte{}, err
	}
	v, err := fromBytes(value)
	if err != nil {
		return [16]byte{}, err
	}
	// xor with key
	for i := 0; i < 4; i++ {
		v[i] ^= mk[i]
	}

	// permutations
	for i := 0; i < 16; i++ {
		v[0] += v[1]
		v[1] = ROTR32(v[1], 27) ^ v[0]
		v[2] += v[3]
		v[3] = ROTR32(v[3], 24) ^ v[2]
		v[2] += v[1]
		v[0] = ROTR32(v[0], 16) + v[3]
		v[3] = ROTR32(v[3], 19) ^ v[0]
		v[1] = ROTR32(v[1], 25) ^ v[2]
		v[2] = ROTR32(v[2], 16)
	}

	// xor with key
	for i := 0; i < 4; i++ {
		v[i] ^= mk[i]
	}

	return fromUints(v)
}

// DonutEncrypt encrypts and decrypts donut data
func DonutEncrypt(masterKey, counter [16]byte, data []byte) ([]byte, [16]byte, error) {
	for i := 0; i < len(data); i += 16 {
		// encrypt the counter
		enc, err := Chaskey(masterKey, counter)
		if err != nil {
			return nil, [16]byte{}, err
		}

		// xor data with encrypted counter
		for j, v := range enc {
			offset := i + j
			if offset >= len(data) {
				break
			}
			data[offset] ^= v
		}

		for j := 15; j > -1; j-- {
			counter[j]++
			if counter[j] != 0 {
				break
			}
		}
	}
	return data, counter, nil
}
