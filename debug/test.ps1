Set-Location C:\Dev\SuperDuperGoCrypto\debug

.\file.exe -GenerateKeyPair -PrivateKeyFile="private1.json"
.\file.exe -ExtractPublicKey -PrivateKeyFile="private1.json" -PublicKeyFile="public1.json"

.\file.exe -GenerateKeyPair -PrivateKeyFile="private2.json"
.\file.exe -ExtractPublicKey -PrivateKeyFile="private2.json" -PublicKeyFile="public2.json"

$key1 = .\file.exe -CreateKeyAgreement -PrivateKeyFile="private1.json" -PublicKeyFile="public2.json"
$key2 = .\file.exe -CreateKeyAgreement -PrivateKeyFile="private2.json" -PublicKeyFile="public1.json"

if ($key1 -eq $key2) {
    Write-Host "CreateKeyAgreement is OK" -ForegroundColor Green
}else {
    Write-Host "CreateKeyAgreement is NOT OK" -ForegroundColor Red
}