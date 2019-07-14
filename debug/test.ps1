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