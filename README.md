# SuperDuperGoCrypto

> NEVER never use this anywhere! Just for fun!

[![CircleCI](https://circleci.com/gh/dhcgn/SuperDuperGoCrypto.svg?style=svg)](https://circleci.com/gh/dhcgn/SuperDuperGoCrypto)
[![Go Report Card](https://goreportcard.com/badge/github.com/dhcgn/SuperDuperGoCrypto)](https://goreportcard.com/report/github.com/dhcgn/SuperDuperGoCrypto)

Encryption with post-quantum cryptography safe supersingular isogeny and X448 key exchange and ChaCha20-Poly1305 AEAD for symmetric  encryption.

```powershell
Set-Location C:\Dev\SuperDuperGoCrypto\debug

Remove-Item *.json

.\file.exe -GenerateKeyPair -PrivateKeyFile="private1.json"
.\file.exe -ExtractPublicKey -PrivateKeyFile="private1.json" -PublicKeyFile="public1.json"

.\file.exe -GenerateKeyPair -PrivateKeyFile="private2.json"
.\file.exe -ExtractPublicKey -PrivateKeyFile="private2.json" -PublicKeyFile="public2.json"

Set-Content -Value "Hallo World!" -Path plain.txt
.\file.exe -Encrypt -PublicKeyFile="public1.json" -PlainFile plain.txt -CipherFile cipher.json
.\file.exe -Decrypt -PrivateKeyFile="private1.json" -PlainFile plain_decrypted.txt -CipherFile cipher.json

Write-Host ("Plain:   {0}" -f (Get-Content plain.txt))
Write-Host ("Decrypt: {0}" -f (Get-Content plain_decrypted.txt))

if ((Get-Content plain.txt) -eq (Get-Content plain_decrypted.txt)) {
    Write-Host "OK" -ForegroundColor Green
}else {
    Write-Host "Error" -ForegroundColor Red
}
```
