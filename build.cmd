
set version=%1
set key=%2

cd %~dp0

dotnet build magic.lambda.crypto/magic.lambda.crypto.csproj --configuration Release --source https://api.nuget.org/v3/index.json
dotnet nuget push magic.lambda.crypto/bin/Release/magic.lambda.crypto.%version%.nupkg -k %key% -s https://api.nuget.org/v3/index.json
