Get-Module ActiveDirectory

$myusername ="myusername"
$name = "GroupName"
$des = "Description"
$path = "Path"


New-ADGroup -Name $name -Description $des -GroupCategory Security -GroupScope Global -Path $path
Add-ADGroupMember -Identity $name -Members $myusername

$user = Import-Csv C:\Users\Username\FileName.csv

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