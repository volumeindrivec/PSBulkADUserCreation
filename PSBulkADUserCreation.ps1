#Csv Header == First Name,Last Name,Username,Company,OU,Login Script,GroupsSamAccountNames,DefaultPassword,Enabled
#Group seperator must be semicolon (;), no spaces between groups, uses SAM Account Name
Function Add-BulkADUsers {
    [CmdletBinding()]
    param(
        [string]$UserPrincipalNameSuffix = "@contoso.com",
        [string]$BaseDN = "OU=Users,DC=contoso,DC=com",
        [string]$CsvPath = "C:\Scripts\newusers.csv"
    )
    
    Import-Module ActiveDirectory

    $newusers = Import-Csv -Path $CsvPath
    

    foreach ($user in $newusers){
        Try {
            $SAMAccountName = $user.Username
            $Surname =  $User.'First Name'
            $GivenName = $User.'Last Name'
            $DisplayName =  $user.'First Name' + " " + $user.'Last Name' # + " (" + $user.Company + ")"
            $ScriptPath = $user.'Login Script'
            $Company = $user.Company
            $Description = $null #"Contractor - $Company"
            $DefaultPassword = $user.DefaultPassword
            $Groups = $user.GroupsSamAccountNames.Split(";")
            $Enabled = [System.Convert]::ToBoolean($user.Enabled)
            if ($user.OU -eq ""){
                $Path = $BaseDN
            }
            else {
                $Path = $user.OU + "," + $BaseDN
            }  
            $UserPrincipalName = $SAMAccountName + $UserPrincipalNameSuffix


            Write-Verbose "SAMAccountName            : $SAMAccountName"
            Write-Verbose "Surname                   : $Surname"
            Write-Verbose "Given Name                : $GivenName"
            Write-Verbose "Display Name              : $DisplayName"
            Write-Verbose "Script Path               : $ScriptPath"
            Write-Verbose "Path (OU)                 : $Path"
            Write-Verbose "User Principal Name (UPN) : $UserPrincipalName"
            Write-Verbose "Description               : $Description"
            Write-Verbose "Default Password          : $DefaultPassword"
            foreach ($g in $Groups){ Write-Verbose "Group, Member Of          : $g" }
            Write-Verbose ""

            New-ADUser -Name $DisplayName -SAMAccountName $SAMAccountName -Surname $Surname -GivenName $GivenName -ScriptPath $ScriptPath -Path $Path -UserPrincipalName $UserPrincipalName -Description $Description
            $securePassword = ConvertTo-SecureString -AsPlainText $DefaultPassword -Force
            Set-ADAccountPassword -Identity $SAMAccountName -NewPassword $securePassword -Reset
            if ($Enabled){
                Set-ADUser -Identity $SAMAccountName -Enabled $true
            }
            foreach ($group in $Groups){
                if ($group -ne ''){
                    Try {
                        Add-ADGroupMember -Identity $group -Members $SAMAccountName
                    }
                    Catch {
                        Write-Output "ERROR - Unable to add $DisplayName to $group"
                    }  
                }
            }
        }
        Catch {
            Write-Output "Some error occured.  No con permiso.  '$DisplayName' was skipped."
        }
    }
}