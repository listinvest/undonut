undonut
=======

An unpacker for [donut](https://github.com/TheWover/donut) shellcode.

Building
--------

Building requires Go

    go build -o undonut cmd/undonut.go

Usage
-----

undonut will parse the donut instance in the shellcode and decrypt tha payload, printing relevant configuration.

```
% ./undonut -shellcode beacon.bin
Donut Instance:
 [*] Size: 343896
 [*] Instance Master Key: [83 163 3 41 148 80 83 145 192 242 7 77 95 50 239 155]
 [*] Instance Nonce: [184 3 152 176 238 59 229 183 37 41 245 45 118 154 117 70]
 [*] IV: 1b14f22e00000000
 [*] Exit Option: EXIT_OPTION_THREAD
 [*] Entropy: ENTROPY_DEFAULT
 [*] DLLs: ole32;oleaut32;wininet;mscoree;shell32
 [*] AMSI Bypass: BYPASS_CONTINUE
 [*] Instance Type: INSTANCE_EMBED
 [*] Module Master Key: [103 180 138 193 95 78 101 84 225 120 227 163 165 217 29 140]
 [*] Module Nonce: [147 238 93 228 82 26 155 0 24 177 70 38 77 76 90 180]
 [*] Module Type: MODULE_EXE
 [*] Module Compression: COMPRESS_NONE
```

With the `-recover` flag specified, undonut will attempt to recover the shellcode in it's raw format (decompression not currently supported)

Support
-------

undonut currently supports unpacking payloads generated with donut `v0.9.3`
