## Solution to D^3CTF2021 Zigzag Encryptor

[中文](./readme_zhcn.md)

1. Analyze the zigzag encoding and recover the encrypted bytes.
2. Analyze the LFSR encryptor, use the information we already know(the message prefix) to recover the *initial vector* and *polynomial* used when encrypting the original message.
3. Re-generate the key sequence, recover the original message.

For details, please see the solution script.