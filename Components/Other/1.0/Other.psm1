<#
    Copyright (C) 2022  KeepCodeOpen - The ultimate IT-Support dashboard
    <https://stolpe.io>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
#>

function ConvertTo-ByteString {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline = $true)]
        $byteCount
    )

    Process {
        $suf = @( "B", "KB", "MB", "GB", "TB", "PB", "EB" )
        if ($byteCount -eq 0) {
            return "0" + $suf[0];
        }
            
        $bytes = [Math]::Abs($byteCount);
        $place = [Convert]::ToInt32([Math]::Floor([Math]::Log($bytes, 1024)))
        $num = [Math]::Round($bytes / [Math]::Pow(1024, $place), 1)
        return ([Math]::Sign($byteCount) * $num).ToString() + $suf[$place]
    }
}
function New-RndPassword {
    [CmdletBinding()]
    param(
        [ValidateRange(8, 30)]
        [int]$Length = 10,
        [ValidateRange(1, 7)]
        [int]$SpecialCharacters = 1
    )

    $C = 'abcdefghiklmnoprstuvwxyzABCDEFGHKLMNOPRSTUVWXYZ1234567890'
    $randomC = 1..$($Length - $SpecialCharacters) | ForEach-Object { Get-Random -Maximum $C.length } 
    
    $SC = '!§$%&/()=?'
    $randomSC = 1..$SpecialCharacters | ForEach-Object { Get-Random -Maximum $SC.length }

    $private:ofs = "" 
    $inputString = [String]$C[$randomC]
    $inputString += [String]$SC[$randomSC]

    $characterArray = $inputString.ToCharArray()   
    $scrambledStringArray = $characterArray | Get-Random -Count $characterArray.Length     
    $outputString = -join $scrambledStringArray
    return $outputString 
}

Export-ModuleMember -Function "ConvertTo-ByteString", "New-RndPassword"