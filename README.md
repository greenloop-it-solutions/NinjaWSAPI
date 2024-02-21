To get started, download the ZIP and extract into your PowerShell 'modules' directory. Should also work with https://github.com/PsModuleInstall/FromGithub

To load:

```Import-Module NinjaWSAPI```

To create a new session:
```
$NINJA_BASE_FQDN = "greenloop.rmmservice.com"

$adminUsername = Read-Host "Provide an admin username"
$adminPassword = Read-Host "Provide the password for this user"
$MFASECRET = Read-Host "Provide the OTP-Secret for this user"

Import-Module NinjaWSAPI

$Params = [ordered]@{
    username = $adminUsername 
    userPassword = $adminPassword
    mfatoken = get-otp -WINDOW 30 -LENGTH 6 -SECRET $MFASECRET
}

#use myKey as your $SESSIONKEY for subsequent calls to NinjaWS functions
$myKey = New-NinjaWSSession @Params
```
