
Get-Module ActiveDirectory

#tao OU

New-ADOrganizationalUnit -Name "KHOA_CNTT" -Path "DC=labtdtu,DC=com"

New-ADOrganizationalUnit -Name "Leader" -Path "OU=KHOA_CNTT,DC=labtdtu,DC=com"

New-ADOrganizationalUnit -Name "Office" -Path "OU=KHOA_CNTT,DC=labtdtu,DC=com"

New-ADOrganizationalUnit -Name "Qualification" -Path "OU=KHOA_CNTT,DC=labtdtu,DC=com"


#tao cac user duoc uy quyen


$user = Import-Csv C:\Users\Administrator\User.csv

foreach ($u in $user){

    $username = $u.Username
    $password = $u.Password
    $firstname = $u.Firstname
    $lastname = $u.Lastname
    $fullname = $u.Fullname
    $department = $u.Department
    $OU = $u.OU
    $g = $u.Group
    $g2 = $u.Group2

     New-ADUser `
        -SamAccountName $username `
        -UserPrincipalName "$username@labtdtu.com" `
        -Name $fullname `
        -GivenName $firstname `
        -Surname $lastname `
        -Enabled $true `
        -ChangePasswordAtLogon $false `
        -PasswordNeverExpires $true `
        -DisplayName "$lastname, $firstname" `
        -Department $department `
        -Path $OU `
        -AccountPassword (ConvertTo-SecureString $password -AsPlainText -Force) 

    
     Add-ADGroupMember -Identity $g -Members $username

     if($g2 -ne ''){
        Add-ADGroupMember -Identity $g2 -Members $username
     }


    

 }


 
#uy quyen cac user vua tao
 
dsacls "OU=Qualification,OU=KHOA_CNTT,DC=LABTDTU,DC=COM" /G "LABTDTU\tutd:CCDC;user"
dsacls "OU=Qualification,OU=KHOA_CNTT,DC=LABTDTU,DC=COM" /I:S /G "LABTDTU\tutd:GA;;user"

dsacls "OU=Qualification,OU=KHOA_CNTT,DC=LABTDTU,DC=COM" /G "LABTDTU\tutd:CCDC;group"
dsacls "OU=Qualification,OU=KHOA_CNTT,DC=LABTDTU,DC=COM" /I:S /G "LABTDTU\tutd:GA;;group"
 
dsacls "OU=Leader,OU=KHOA_CNTT,DC=LABTDTU,DC=COM" /G "LABTDTU\tutd:CCDC;user"
dsacls "OU=Leader,OU=KHOA_CNTT,DC=LABTDTU,DC=COM" /I:S /G "LABTDTU\tutd:GA;;user"

dsacls "OU=Leader,OU=KHOA_CNTT,DC=LABTDTU,DC=COM" /G "LABTDTU\tutd:CCDC;group"
dsacls "OU=Leader,OU=KHOA_CNTT,DC=LABTDTU,DC=COM" /I:S /G "LABTDTU\tutd:GA;;group"





dsacls "OU=Qualification,OU=KHOA_CNTT,DC=LABTDTU,DC=COM" /G "LABTDTU\phuoctt:CCDC;user"
dsacls "OU=Qualification,OU=KHOA_CNTT,DC=LABTDTU,DC=COM" /I:S /G "LABTDTU\phuoctt:GA;;user"


dsacls "OU=Qualification,OU=KHOA_CNTT,DC=LABTDTU,DC=COM" /G "LABTDTU\phuoctt:CCDC;group"
dsacls "OU=Qualification,OU=KHOA_CNTT,DC=LABTDTU,DC=COM" /I:S /G "LABTDTU\phuoctt:GA;;group"




dsacls "OU=Qualification,OU=KHOA_CNTT,DC=LABTDTU,DC=COM" /G "LABTDTU\cuongla:CCDC;user"
dsacls "OU=Qualification,OU=KHOA_CNTT,DC=LABTDTU,DC=COM" /I:S /G "LABTDTU\cuongla:GA;;user"


dsacls "OU=Qualification,OU=KHOA_CNTT,DC=LABTDTU,DC=COM" /G "LABTDTU\cuongla:CCDC;group"
dsacls "OU=Qualification,OU=KHOA_CNTT,DC=LABTDTU,DC=COM" /I:S /G "LABTDTU\cuongla:GA;;group"



dsacls "OU=Office,OU=KHOA_CNTT,DC=LABTDTU,DC=COM" /G "LABTDTU\phungcp:CCDC;user"
dsacls "OU=Office,OU=KHOA_CNTT,DC=LABTDTU,DC=COM" /I:S /G "LABTDTU\phungcp:GA;;user"


dsacls "OU=Office,OU=KHOA_CNTT,DC=LABTDTU,DC=COM" /G "LABTDTU\phungcp:CCDC;group"
dsacls "OU=Office,OU=KHOA_CNTT,DC=LABTDTU,DC=COM" /I:S /G "LABTDTU\phungcp:GA;;group"


















