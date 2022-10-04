
<#
.SYNOPSIS
   This Script is meant to run as a Function App. The purpose is to query a VNET and return a CIDR address space based on user input. Exact same function as https://github.com/gamullen/FindNextCIDRRange but written in Powershell instead of C# so it is slower but a more familiar language to scripters.
.DESCRIPTION
   More details can be found at https://automationadmin.com/2022/08/tf-get-next-subnet.
.NOTES
   Change log:
   2022-10-04 - Gerry Williams - Initial Version.
#>

using namespace System.Net

param($Request, $TriggerMetadata)

[string]$SubscriptionID = $Request.Query.subscriptionId
[string]$VnetRG = $Request.Query.resourceGroupName
[string]$VnetName = $Request.Query.virtualNetworkName
[string]$DesiredCidr = $Request.Query.cidr
Write-Output "Input param subscriptionId : $SubscriptionID"
Write-Output "Input param resourceGroupName : $VnetRG"
Write-Output "Input param virtualNetworkName : $VnetName"
Write-Output "Input param cidr : $DesiredCidr"


$PreviousCidrs = [System.Collections.Generic.List[PSObject]]@()

If ( $Request.Query.ContainsKey("previousblock"))
{
   [string]$CidrsInput = $Request.Query.previousblock
   Write-Output "Input param previousblock : $CidrsInput"
}

If ( $null -eq $CidrsInput)
{
   Write-Output "Input param previousblock is empty"
}
Else
{

   If ( $CidrsInput.Contains(",") )
   {
      $splitCidrs = $CidrsInput.Split(",") 
      Foreach ( $splitCidr in $splitCidrs)
      {
         
         If ( $splitCidr.Contains("/") )
         {
            [void]$PreviousCidrs.add($splitCidr)
         }
         Else
         {
            $jsonResponse = @{
               "details"        = "ERROR: previousBlock must be in cidr notation"
               "proposedCIDR"   = ""
               "functionInputs" = @{
                  SubscriptionID = $SubscriptionID
                  VnetRG         = $VnetRG
                  VnetName       = $VnetName
                  Cidr           = $DesiredCidr
                  PreviousCidrs  = $PreviousCidrs
               }
         
            } | ConvertTo-Json -Depth 4
         
         
            Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
                  StatusCode = [HttpStatusCode]::OK
                  Body       = $jsonResponse   
               })
            Exit 0 
         }
      }
   }
   Else
   {
      If ( $CidrsInput.Contains("/") )
      {
         [void]$PreviousCidrs.add($CidrsInput)
      }
      Else
      {
         $jsonResponse = @{
            "details"        = "ERROR: previousBlock must be in cidr notation"
            "proposedCIDR"   = ""
            "functionInputs" = @{
               SubscriptionID = $SubscriptionID
               VnetRG         = $VnetRG
               VnetName       = $VnetName
               Cidr           = $DesiredCidr
               PreviousCidrs  = $PreviousCidrs
            }
         
         } | ConvertTo-Json -Depth 4
         
         
         Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
               StatusCode = [HttpStatusCode]::OK
               Body       = $jsonResponse   
            })
         Exit 0 
      }
   }
}

##################################################################################################################################################################
#region Functions
##################################################################################################################################################################
# Retrieved 2022-10-04 from https://github.com/indented-automation/Indented.Net.IP/blob/main/Indented.Net.IP/private/ConvertToNetwork.ps1
function ConvertToNetwork
{
   <#
   .SYNOPSIS
       Converts IP address formats to a set a known styles.
   .DESCRIPTION
       ConvertToNetwork ensures consistent values are recorded from parameters which must handle differing addressing formats. This Cmdlet allows all other the other functions in this module to offload parameter handling.
   .NOTES
       Change log:
           05/03/2016 - Chris Dent - Refactored and simplified.
           14/01/2014 - Chris Dent - Created.
   #>

   [CmdletBinding()]
   [OutputType('Indented.Net.IP.Network')]
   param (
      # Either a literal IP address, a network range expressed as CIDR notation, or an IP address and subnet mask in a string.
      [Parameter(Mandatory = $true, Position = 1)]
      [String]$IPAddress,

      # A subnet mask as an IP address.
      [Parameter(Position = 2)]
      [AllowNull()]
      [String]$SubnetMask
   )

   $validSubnetMaskValues = @(
      "0.0.0.0", "128.0.0.0", "192.0.0.0",
      "224.0.0.0", "240.0.0.0", "248.0.0.0", "252.0.0.0",
      "254.0.0.0", "255.0.0.0", "255.128.0.0", "255.192.0.0",
      "255.224.0.0", "255.240.0.0", "255.248.0.0", "255.252.0.0",
      "255.254.0.0", "255.255.0.0", "255.255.128.0", "255.255.192.0",
      "255.255.224.0", "255.255.240.0", "255.255.248.0", "255.255.252.0",
      "255.255.254.0", "255.255.255.0", "255.255.255.128", "255.255.255.192",
      "255.255.255.224", "255.255.255.240", "255.255.255.248", "255.255.255.252",
      "255.255.255.254", "255.255.255.255"
   )

   $network = [PSCustomObject]@{
      IPAddress  = $null
      SubnetMask = $null
      MaskLength = 0
      PSTypeName = 'Indented.Net.IP.Network'
   }

   # Override ToString
   $network | Add-Member ToString -MemberType ScriptMethod -Force -Value {
      '{0}/{1}' -f $this.IPAddress, $this.MaskLength
   }

   if (-not $PSBoundParameters.ContainsKey('SubnetMask') -or $SubnetMask -eq '')
   {
      $IPAddress, $SubnetMask = $IPAddress.Split([Char[]]'\/ ', [StringSplitOptions]::RemoveEmptyEntries)
   }

   # IPAddress

   while ($IPAddress.Split('.').Count -lt 4)
   {
      $IPAddress += '.0'
   }

   if ([IPAddress]::TryParse($IPAddress, [Ref]$null))
   {
      $network.IPAddress = [IPAddress]$IPAddress
   }
   else
   {
      $errorRecord = [System.Management.Automation.ErrorRecord]::new(
         [ArgumentException]'Invalid IP address.',
         'InvalidIPAddress',
         'InvalidArgument',
         $IPAddress
      )
      $PSCmdlet.ThrowTerminatingError($errorRecord)
   }

   # SubnetMask

   if ($null -eq $SubnetMask -or $SubnetMask -eq '')
   {
      $network.SubnetMask = [IPAddress]$validSubnetMaskValues[32]
      $network.MaskLength = 32
   }
   else
   {
      $maskLength = 0
      if ([Int32]::TryParse($SubnetMask, [Ref]$maskLength))
      {
         if ($MaskLength -ge 0 -and $maskLength -le 32)
         {
            $network.SubnetMask = [IPAddress]$validSubnetMaskValues[$maskLength]
            $network.MaskLength = $maskLength
         }
         else
         {
            $errorRecord = [System.Management.Automation.ErrorRecord]::new(
               [ArgumentException]'Mask length out of range (expecting 0 to 32).',
               'InvalidMaskLength',
               'InvalidArgument',
               $SubnetMask
            )
            $PSCmdlet.ThrowTerminatingError($errorRecord)
         }
      }
      else
      {
         while ($SubnetMask.Split('.').Count -lt 4)
         {
            $SubnetMask += '.0'
         }
         $maskLength = $validSubnetMaskValues.IndexOf($SubnetMask)

         if ($maskLength -ge 0)
         {
            $Network.SubnetMask = [IPAddress]$SubnetMask
            $Network.MaskLength = $maskLength
         }
         else
         {
            $errorRecord = [System.Management.Automation.ErrorRecord]::new(
               [ArgumentException]'Invalid subnet mask.',
               'InvalidSubnetMask',
               'InvalidArgument',
               $SubnetMask
            )
            $PSCmdlet.ThrowTerminatingError($errorRecord)
         }
      }
   }

   $network
}

# Retrieved 2022-10-04 from https://github.com/indented-automation/Indented.Net.IP/blob/main/Indented.Net.IP/public/Test-SubnetMember.ps1
function Test-SubnetMember
{
   <#
   .SYNOPSIS
       Tests an IP address to determine if it falls within IP address range.
   .DESCRIPTION
       Test-SubnetMember attempts to determine whether or not an address or range falls within another range. The network and broadcast address are calculated the converted to decimal then compared to the decimal form of the submitted address.
   .EXAMPLE
       Test-SubnetMember -SubjectIPAddress 10.0.0.0/24 -ObjectIPAddress 10.0.0.0/16
       Returns true as the subject network can be contained within the object network.
   .EXAMPLE
       Test-SubnetMember -SubjectIPAddress 192.168.0.0/16 -ObjectIPAddress 192.168.0.0/24
       Returns false as the subject network is larger the object network.
   .EXAMPLE
       Test-SubnetMember -SubjectIPAddress 10.2.3.4/32 -ObjectIPAddress 10.0.0.0/8
       Returns true as the subject IP address is within the object network.
   .EXAMPLE
       Test-SubnetMember -SubjectIPAddress 255.255.255.255 -ObjectIPAddress 0/0
       Returns true as the subject IP address is the last in the object network range.
   #>

   [CmdletBinding()]
   [OutputType([bool])]
   param (
      # A representation of the subject, the network to be tested. Either a literal IP address, a network range expressed as CIDR notation, or an IP address and subnet mask in a string.
      [Parameter(Mandatory, Position = 1)]
      [string]$SubjectIPAddress,

      # A representation of the object, the network to test against. Either a literal IP address, a network range expressed as CIDR notation, or an IP address and subnet mask in a string.
      [Parameter(Mandatory, Position = 2)]
      [string]$ObjectIPAddress,

      # A subnet mask as an IP address.
      [string]$SubjectSubnetMask,

      # A subnet mask as an IP address.
      [string]$ObjectSubnetMask
   )

   try
   {
      $subjectNetwork = ConvertToNetwork $SubjectIPAddress $SubjectSubnetMask
      $objectNetwork = ConvertToNetwork $ObjectIPAddress $ObjectSubnetMask
   }
   catch
   {
      throw $_
   }

   # A simple check, if the mask is shorter (larger network) then it won't be a subnet of the object anyway.
   if ($subjectNetwork.MaskLength -lt $objectNetwork.MaskLength)
   {
      return $false
   }

   $subjectDecimalIP = ConvertTo-DecimalIP $subjectNetwork.IPAddress
   $objectDecimalNetwork = ConvertTo-DecimalIP (Get-NetworkAddress $objectNetwork)
   $objectDecimalBroadcast = ConvertTo-DecimalIP (Get-BroadcastAddress $objectNetwork)

   # If the mask is longer (smaller network), then the decimal form of the address must be between the
   # network and broadcast address of the object (the network we test against).
   if ($subjectDecimalIP -ge $objectDecimalNetwork -and $subjectDecimalIP -le $objectDecimalBroadcast)
   {
      return $true
   }
   else
   {
      return $false
   }
}

# Retrieved 2022-10-04 from https://github.com/indented-automation/Indented.Net.IP/blob/main/Indented.Net.IP/public/ConvertTo-DecimalIP.ps1
function ConvertTo-DecimalIP
{
   <#
   .SYNOPSIS
       Converts a Decimal IP address into a 32-bit unsigned integer.
   .DESCRIPTION
       ConvertTo-DecimalIP takes a decimal IP, uses a shift operation on each octet and returns a single UInt32 value.
   .INPUTS
       System.Net.IPAddress
   .EXAMPLE
       ConvertTo-DecimalIP 1.2.3.4
       Converts an IP address to an unsigned 32-bit integer value.
   #>

   [CmdletBinding()]
   [OutputType([UInt32])]
   param (
      # An IP Address to convert.
      [Parameter(Mandatory, Position = 1, ValueFromPipeline )]
      [IPAddress]$IPAddress
   )

   process
   {
      [UInt32]([IPAddress]::HostToNetworkOrder($IPAddress.Address) -shr 32 -band [UInt32]::MaxValue)
   }
}

# Retrieved 2022-10-04 from https://github.com/indented-automation/Indented.Net.IP/blob/main/Indented.Net.IP/public/Get-NetworkAddress.ps1
function Get-NetworkAddress
{
   <#
   .SYNOPSIS
       Get the network address for a network range.
   .DESCRIPTION
       Get-NetworkAddress returns the network address for a subnet by performing a bitwise AND operation against the decimal forms of the IP address and subnet mask.
   .INPUTS
       System.String
   .EXAMPLE
       Get-NetworkAddress 192.168.0.243 255.255.255.0
       Returns the address 192.168.0.0.
   .EXAMPLE
       Get-NetworkAddress 10.0.9/22
       Returns the address 10.0.8.0.
   .EXAMPLE
       Get-NetworkAddress "10.0.23.21 255.255.255.224"
       Input values are automatically split into IP address and subnet mask. Returns the address 10.0.23.0.
   #>

   [CmdletBinding()]
   [OutputType([IPAddress])]
   param (
      # Either a literal IP address, a network range expressed as CIDR notation, or an IP address and subnet mask in a string.
      [Parameter(Mandatory, Position = 1, ValueFromPipeline)]
      [string]$IPAddress,

      # A subnet mask as an IP address.
      [Parameter(Position = 2)]
      [string]$SubnetMask
   )

   process
   {
      try
      {
         $network = ConvertToNetwork @PSBoundParameters

         return [IPAddress]($network.IPAddress.Address -band $network.SubnetMask.Address)
      }
      catch
      {
         Write-Error -ErrorRecord $_
      }
   }
}

# Retrieved 2022-10-04 from https://github.com/indented-automation/Indented.Net.IP/blob/main/Indented.Net.IP/public/Get-BroadcastAddress.ps1
function Get-BroadcastAddress
{
   <#
   .SYNOPSIS
       Get the broadcast address for a network range.
   .DESCRIPTION
       Get-BroadcastAddress returns the broadcast address for a subnet by performing a bitwise AND operation against the decimal forms of the IP address and inverted subnet mask.
   .INPUTS
       System.String
   .EXAMPLE
       Get-BroadcastAddress 192.168.0.243 255.255.255.0
       Returns the address 192.168.0.255.
   .EXAMPLE
       Get-BroadcastAddress 10.0.9/22
       Returns the address 10.0.11.255.
   .EXAMPLE
       Get-BroadcastAddress 0/0
       Returns the address 255.255.255.255.
   .EXAMPLE
       Get-BroadcastAddress "10.0.0.42 255.255.255.252"
       Input values are automatically split into IP address and subnet mask. Returns the address 10.0.0.43.
   #>

   [CmdletBinding()]
   [OutputType([IPAddress])]
   param (
      # Either a literal IP address, a network range expressed as CIDR notation, or an IP address and subnet mask in a string.
      [Parameter(Mandatory, Position = 1, ValueFromPipeline)]
      [string]$IPAddress,

      # A subnet mask as an IP address.
      [Parameter(Position = 2)]
      [string]$SubnetMask
   )

   process
   {
      try
      {
         $network = ConvertToNetwork @PSBoundParameters

         $networkAddress = [IPAddress]($network.IPAddress.Address -band $network.SubnetMask.Address)

         return [IPAddress](
            $networkAddress.Address -bor
            -bnot $network.SubnetMask.Address -band
            -bnot ([Int64][UInt32]::MaxValue -shl 32)
         )
      }
      catch
      {
         Write-Error -ErrorRecord $_
      }
   }
}

function Split-IPv4Subnet
{
   ###############################################################################################################
   # Language     :  PowerShell 4.0
   # Filename     :  Split-IPv4Subnet.ps1
   # Autor        :  BornToBeRoot (https://github.com/BornToBeRoot)
   # Description  :  Split a subnet in multiple subnets with given subnetmasks
   # Repository   :  https://github.com/BornToBeRoot/PowerShell
   ###############################################################################################################

   <#
      .SYNOPSIS
      Split a subnet in multiple subnets with given subnetmasks
      
      .DESCRIPTION
      Split a subnet in multiple subnets with given subnetmasks. Each new subnet contains NetworkID, Broadcast, total available IPs and usable IPs for hosts.
      
      .EXAMPLE
      Split-IPv4Subnet -IPv4Address 192.168.0.0 -CIDR 22 -NewCIDR 24
      NetworkID   Broadcast     IPs Hosts
      ---------   ---------     --- -----
      192.168.0.0 192.168.0.255 256   254
      192.168.1.0 192.168.1.255 256   254
      192.168.2.0 192.168.2.255 256   254
      192.168.3.0 192.168.3.255 256   254
      .EXAMPLE
      Split-IPv4Subnet -IPv4Address 192.168.0.0 -Mask 255.255.255.0 -NewMask 255.255.255.128
      NetworkID     Broadcast     IPs Hosts
      ---------     ---------     --- -----
      192.168.0.0   192.168.0.127 128   126
      192.168.0.128 192.168.0.255 128   126
      
      .LINK
      https://github.com/BornToBeRoot/PowerShell/blob/master/Documentation/Function/Split-IPv4Subnet.README.md
   #>
   [CmdletBinding(DefaultParameterSetName = 'CIDR')]
   param(
      [Parameter(
         Position = 0,
         Mandatory = $true,
         HelpMessage = 'IPv4-Address which is in the subnet')]
      [IPAddress]$IPv4Address,

      [Parameter(
         ParameterSetName = 'CIDR',
         Position = 1,
         Mandatory = $true,
         HelpMessage = 'CIDR like /24 without "/"')]
      [ValidateRange(0, 31)]
      [Int32]$CIDR,

      [Parameter(
         ParameterSetName = 'CIDR',
         Position = 2,
         Mandatory = $true,
         HelpMessage = 'New CIDR like /28 without "/"')]
      [ValidateRange(0, 31)]
      [Int32]$NewCIDR,

      [Parameter(
         ParameterSetName = 'Mask',
         Position = 1,
         Mandatory = $true,
         Helpmessage = 'Subnetmask like 255.255.255.0')]
      [ValidateScript({
            if ($_ -match "^(254|252|248|240|224|192|128).0.0.0$|^255.(254|252|248|240|224|192|128|0).0.0$|^255.255.(254|252|248|240|224|192|128|0).0$|^255.255.255.(254|252|248|240|224|192|128|0)$")
            {
               return $true
            }
            else
            {
               throw "Enter a valid subnetmask (like 255.255.255.0)!"
            }
         })]
      [String]$Mask,

      [Parameter(
         ParameterSetName = 'Mask',
         Position = 2,
         Mandatory = $true,
         HelpMessage = 'Subnetmask like 255.255.255.128')]
      [ValidateScript({
            if ($_ -match "^(254|252|248|240|224|192|128).0.0.0$|^255.(254|252|248|240|224|192|128|0).0.0$|^255.255.(254|252|248|240|224|192|128|0).0$|^255.255.255.(254|252|248|240|224|192|128|0)$")
            {
               return $true
            }
            else 
            {
               throw "Enter a valid subnetmask (like 255.255.255.0)!"
            }
         })]
      [String]$NewMask  
   )

   Begin
   {
   }

   Process
   {
      if ($PSCmdlet.ParameterSetName -eq 'Mask')
      {
         $CIDR = (Convert-Subnetmask -Mask $Mask).CIDR 
         $NewCIDR = (Convert-Subnetmask -Mask $NewMask).CIDR
      }
        
      if ($CIDR -ge $NewCIDR)
      {
         return "Subnet (/$CIDR) can't be greater or equal than new subnet (/$NewCIDR)"
      }

      # Calculate the current Subnet
      $Subnet = Get-IPv4Subnet -IPv4Address $IPv4Address -CIDR $CIDR
        
      # Get new  HostBits based on SubnetBits (CIDR) // Hostbits (32 - /24 = 8 -> 00000000000000000000000011111111)
      $NewHostBits = ('1' * (32 - $NewCIDR)).PadLeft(32, "0")

      # Convert Bits to Int64, add +1 to get all available IPs
      $NewAvailableIPs = ([Convert]::ToInt64($NewHostBits, 2) + 1)

      # Convert the NetworkID to Int64
      $NetworkID_Int64 = (Convert-IPv4Address -IPv4Address $Subnet.NetworkID).Int64
        
      # Build new subnets, and return them
      for ($i = 0; $i -lt $Subnet.IPs; $i += $NewAvailableIPs)
      {
         Get-IPv4Subnet -IPv4Address (Convert-IPv4Address -Int64 ($NetworkID_Int64 + $i)).IPv4Address -CIDR $NewCIDR
      }
   }

   End
   {

   }
}

function Convert-Subnetmask
{

   <#
    .SYNOPSIS
    Convert a subnetmask to CIDR and vise versa
    .DESCRIPTION
    Convert a subnetmask like 255.255.255 to CIDR (/24) and vise versa.
                
    .EXAMPLE
    Convert-Subnetmask -CIDR 24
    Mask          CIDR
    ----          ----
    255.255.255.0   24
    .EXAMPLE
    Convert-Subnetmask -Mask 255.255.0.0
    Mask        CIDR
    ----        ----
    255.255.0.0   16
    
    .LINK
    https://github.com/BornToBeRoot/PowerShell/blob/master/Documentation/Function/Convert-Subnetmask.README.md
   
   #>
   [CmdLetBinding(DefaultParameterSetName = 'CIDR')]
   param( 
      [Parameter( 
         ParameterSetName = 'CIDR',       
         Position = 0,
         Mandatory = $true,
         HelpMessage = 'CIDR like /24 without "/"')]
      [ValidateRange(0, 32)]
      [Int32]$CIDR,

      [Parameter(
         ParameterSetName = 'Mask',
         Position = 0,
         Mandatory = $true,
         HelpMessage = 'Subnetmask like 255.255.255.0')]
      [ValidateScript({
            if ($_ -match "^(254|252|248|240|224|192|128).0.0.0$|^255.(254|252|248|240|224|192|128|0).0.0$|^255.255.(254|252|248|240|224|192|128|0).0$|^255.255.255.(255|254|252|248|240|224|192|128|0)$")
            {
               return $true
            }
            else 
            {
               throw "Enter a valid subnetmask (like 255.255.255.0)!"    
            }
         })]
      [String]$Mask
   )

   Begin
   {
   }

   Process
   {
      switch ($PSCmdlet.ParameterSetName)
      {
         "CIDR"
         {                          
            # Make a string of bits (24 to 11111111111111111111111100000000)
            $CIDR_Bits = ('1' * $CIDR).PadRight(32, "0")
                
            # Split into groups of 8 bits, convert to Ints, join up into a string
            $Octets = $CIDR_Bits -split '(.{8})' -ne ''
            $Mask = ($Octets | ForEach-Object -Process { [Convert]::ToInt32($_, 2) }) -join '.'
         }

         "Mask"
         {
            # Convert the numbers into 8 bit blocks, join them all together, count the 1
            $Octets = $Mask.ToString().Split(".") | ForEach-Object -Process { [Convert]::ToString($_, 2) }
            $CIDR_Bits = ($Octets -join "").TrimEnd("0")

            # Count the "1" (111111111111111111111111 --> /24)                     
            $CIDR = $CIDR_Bits.Length             
         }               
      }

      [pscustomobject] @{
         Mask = $Mask
         CIDR = $CIDR
      }
   }

   End
   {
   }
}

function Convert-IPv4Address
{

   <#
    .SYNOPSIS
    Convert an IPv4-Address to Int64 and vise versa
    .DESCRIPTION
    Convert an IPv4-Address to Int64 and vise versa. The result will contain the IPv4-Address as string and Tnt64.
    
    .EXAMPLE
    Convert-IPv4Address -IPv4Address "192.168.0.1"   
    IPv4Address      Int64
    -----------      -----
    192.168.0.1 3232235521
    .EXAMPLE
    Convert-IPv4Address -Int64 2886755428
    IPv4Address         Int64
    -----------         -----
    172.16.100.100 2886755428
    .LINK
    https://github.com/BornToBeRoot/PowerShell/blob/master/Documentation/Function/Convert-IPv4Address.README.md
   #>
   [CmdletBinding(DefaultParameterSetName = 'IPv4Address')]
   param(
      [Parameter(
         ParameterSetName = 'IPv4Address',
         Position = 0,
         Mandatory = $true,
         HelpMessage = 'IPv4-Address as string like "192.168.1.1"')]
      [IPAddress]$IPv4Address,

      [Parameter(
         ParameterSetName = 'Int64',
         Position = 0,
         Mandatory = $true,
         HelpMessage = 'IPv4-Address as Int64 like 2886755428')]
      [long]$Int64
   ) 

   Begin
   {
   }

   Process
   {
      switch ($PSCmdlet.ParameterSetName)
      {
         # Convert IPv4-Address as string into Int64
         "IPv4Address"
         {
            $Octets = $IPv4Address.ToString().Split(".")
            $Int64 = [long]([long]$Octets[0] * 16777216 + [long]$Octets[1] * 65536 + [long]$Octets[2] * 256 + [long]$Octets[3]) 
         }
    
         # Convert IPv4-Address as Int64 into string 
         "Int64"
         {            
            $IPv4Address = (([System.Math]::Truncate($Int64 / 16777216)).ToString() + "." + ([System.Math]::Truncate(($Int64 % 16777216) / 65536)).ToString() + "." + ([System.Math]::Truncate(($Int64 % 65536) / 256)).ToString() + "." + ([System.Math]::Truncate($Int64 % 256)).ToString())
         }      
      }

      [pscustomobject] @{    
         IPv4Address = $IPv4Address
         Int64       = $Int64
      }        	
   }

   End
   {
   }      
}

function Get-IPv4Subnet
{

   <#
    .SYNOPSIS
    Calculate a subnet based on an IP-Address and the subnetmask or CIDR
    .DESCRIPTION
    Calculate a subnet based on an IP-Address within the subnet and the subnetmask or CIDR. The result includes the NetworkID, Broadcast, total available IPs and usable IPs for hosts.
                
    .EXAMPLE
    Get-IPv4Subnet -IPv4Address 192.168.24.96 -CIDR 27
    
    NetworkID     Broadcast      IPs Hosts
    ---------     ---------      --- -----
    192.168.24.96 192.168.24.127  32    30
            
    .EXAMPLE
    Get-IPv4Subnet -IPv4Address 192.168.1.0 -Mask 255.255.255.0 | Select-Object -Property *
    NetworkID : 192.168.1.0
    FirstIP   : 192.168.1.1
    LastIP    : 192.168.1.254
    Broadcast : 192.168.1.255
    IPs       : 256
    Hosts     : 254
    .LINK
    https://github.com/BornToBeRoot/PowerShell/blob/master/Documentation/Function/Get-IPv4Subnet.README.md
   #>

   [CmdletBinding(DefaultParameterSetName = 'CIDR')]
   param(
      [Parameter(
         Position = 0,
         Mandatory = $true,
         HelpMessage = 'IPv4-Address which is in the subnet')]
      [IPAddress]$IPv4Address,

      [Parameter(
         ParameterSetName = 'CIDR',
         Position = 1,
         Mandatory = $true,
         HelpMessage = 'CIDR like /24 without "/"')]
      [ValidateRange(0, 31)]
      [Int32]$CIDR,

      [Parameter(
         ParameterSetName = 'Mask',
         Position = 1,
         Mandatory = $true,
         Helpmessage = 'Subnetmask like 255.255.255.0')]
      [ValidateScript({
            if ($_ -match "^(254|252|248|240|224|192|128).0.0.0$|^255.(254|252|248|240|224|192|128|0).0.0$|^255.255.(254|252|248|240|224|192|128|0).0$|^255.255.255.(254|252|248|240|224|192|128|0)$")
            {
               return $true
            }
            else 
            {
               throw "Enter a valid subnetmask (like 255.255.255.0)!"
            }
         })]
      [String]$Mask
   )

   Begin
   {
   }

   Process
   {
      # Convert Mask or CIDR - because we need both in the code below
      switch ($PSCmdlet.ParameterSetName)
      {
         "CIDR"
         {                          
            $Mask = (Convert-Subnetmask -CIDR $CIDR).Mask            
         }

         "Mask"
         {
            $CIDR = (Convert-Subnetmask -Mask $Mask).CIDR          
         }              
      }
        
      # Get CIDR Address by parsing it into an IP-Address
      $CIDRAddress = [System.Net.IPAddress]::Parse([System.Convert]::ToUInt64(("1" * $CIDR).PadRight(32, "0"), 2))
    
      # Binary AND ... this is how subnets work.
      $NetworkID_bAND = $IPv4Address.Address -band $CIDRAddress.Address

      # Return an array of bytes. Then join them.
      $NetworkID = [System.Net.IPAddress]::Parse([System.BitConverter]::GetBytes([UInt32]$NetworkID_bAND) -join ("."))
        
      # Get HostBits based on SubnetBits (CIDR) // Hostbits (32 - /24 = 8 -> 00000000000000000000000011111111)
      $HostBits = ('1' * (32 - $CIDR)).PadLeft(32, "0")
        
      # Convert Bits to Int64
      $AvailableIPs = [Convert]::ToInt64($HostBits, 2)

      # Convert Network Address to Int64
      $NetworkID_Int64 = (Convert-IPv4Address -IPv4Address $NetworkID.ToString()).Int64

      # Calculate the first Host IPv4 Address by add 1 to the Network ID
      $FirstIP = [System.Net.IPAddress]::Parse((Convert-IPv4Address -Int64 ($NetworkID_Int64 + 1)).IPv4Address)

      # Calculate the last Host IPv4 Address by subtract 1 from the Broadcast Address
      $LastIP = [System.Net.IPAddress]::Parse((Convert-IPv4Address -Int64 ($NetworkID_Int64 + ($AvailableIPs - 1))).IPv4Address)

      # Convert add available IPs and parse into IPAddress
      $Broadcast = [System.Net.IPAddress]::Parse((Convert-IPv4Address -Int64 ($NetworkID_Int64 + $AvailableIPs)).IPv4Address)

      # Change useroutput ==> (/27 = 0..31 IPs -> AvailableIPs 32)
      $AvailableIPs += 1

      # Hosts = AvailableIPs - Network Address + Broadcast Address
      $Hosts = ($AvailableIPs - 2)
            
      # Build custom PSObject
      $Result = [pscustomobject] @{
         NetworkID = $NetworkID
         FirstIP   = $FirstIP
         LastIP    = $LastIP
         Broadcast = $Broadcast
         IPs       = $AvailableIPs
         Hosts     = $Hosts
      }

      # Set the default properties
      $Result.PSObject.TypeNames.Insert(0, 'Subnet.Information')

      $DefaultDisplaySet = 'NetworkID', 'Broadcast', 'IPs', 'Hosts'

      $DefaultDisplayPropertySet = New-Object System.Management.Automation.PSPropertySet('DefaultDisplayPropertySet', [string[]]$DefaultDisplaySet)

      $PSStandardMembers = [System.Management.Automation.PSMemberInfo[]]@($DefaultDisplayPropertySet)

      $Result | Add-Member MemberSet PSStandardMembers $PSStandardMembers
        
      # Return the object to the pipeline
      $Result
   }

   End
   {
   }
}

##################################################################################################################################################################
#endregion Functions
##################################################################################################################################################################

Write-Output "Starting Function App Invocation..."

Try
{
   Set-AzContext -Subscription $SubscriptionID -ErrorAction "Stop"
}
Catch
{
   $jsonResponse = @{
      "details"        = "ERROR: Either Subscription does not exist or the Function App managed Identity does not have Read access."
      "proposedCIDR"   = ""
      "functionInputs" = @{
         SubscriptionID = $SubscriptionID
         VnetRG         = $VnetRG
         VnetName       = $VnetName
         Cidr           = $DesiredCidr
         PreviousCidrs  = $PreviousCidrs
      }

   } | ConvertTo-Json -Depth 4


   Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
         StatusCode = [HttpStatusCode]::OK
         Body       = $jsonResponse   
      })
   Exit 0
}

Write-Output "Set subscription: $SubscriptionID"

$UsedSubnetsList = [System.Collections.Generic.List[PSObject]]@()
$CandidateSubnetsList = [System.Collections.Generic.List[PSObject]]@()
$SelectedCandidateSubnetList = [System.Collections.Generic.List[PSObject]]@()

$Vnet = Get-AzVirtualNetwork -Name $VnetName -ResourceGroupName $VnetRG
$VnetAddressSpace = $($vnet.AddressSpace.AddressPrefixes[0]) # We assume only one address space per vnet (most common)
$VnetAddressSpaceIP = $VnetAddressSpace.split("/")[0]
$VnetAddressSpaceCidr = $VnetAddressSpace.split("/")[1]

If ( ($DesiredCidr -as [int]) -le ($VnetAddressSpaceCidr -as [int]) )
{
   $jsonResponse = @{
      "details"        = "ERROR: You cannot request a CIDR larger than the VNET Address Space. VNET Address Space: /$VnetAddressSpaceCidr"
      "proposedCIDR"   = ""
      "functionInputs" = @{
         SubscriptionID = $SubscriptionID
         VnetRG         = $VnetRG
         VnetName       = $VnetName
         Cidr           = $DesiredCidr
         PreviousCidrs  = $PreviousCidrs
      }

   } | ConvertTo-Json -Depth 4


   Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
         StatusCode = [HttpStatusCode]::OK
         Body       = $jsonResponse   
      })
   Exit 0
}

If ( $Vnet.Name.Length -gt 0 )
{
   
   # Add optional list of used Cidrs
   If ( $PreviousCidrs.Count -gt 0 )
   {
      Foreach ($PreviousCidr in $PreviousCidrs)
      {
         $PreviousCidrIP = $PreviousCidr.split("/")[0]
         $PreviousCidrCidr = $PreviousCidr.split("/")[1]
         Write-Output "Previous CIDR IP: $PreviousCidrIP"
         Write-Output "Previous CIDR CIDR: $PreviousCidrCidr"

         # First check that it is not bigger than Vnet address space
         If ( ($PreviousCidrCidr -as [int]) -le ($VnetAddressSpaceCidr -as [int]) )
         {
            $jsonResponse = @{
               "details"        = "ERROR: You cannot request a CIDR larger than the VNET Address Space. VNET Address Space: /$VnetAddressSpaceCidr"
               "proposedCIDR"   = ""
               "functionInputs" = @{
                  SubscriptionID = $SubscriptionID
                  VnetRG         = $VnetRG
                  VnetName       = $VnetName
                  Cidr           = $DesiredCidr
                  PreviousCidrs  = $PreviousCidrs
               }
            
            } | ConvertTo-Json -Depth 4
         
            
            Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
                  StatusCode = [HttpStatusCode]::OK
                  Body       = $jsonResponse   
               })
            Exit 0

         }

         # Next check if it is a valid IP
         Write-Output "Checking if valid..."
         $SubnetVerify = Get-IPv4Subnet -IPv4Address $PreviousCidrIP -CIDR $PreviousCidrCidr -ErrorAction "Stop"

         If ( $SubnetVerify.NetworkID.Length -gt 0)
         {
            [void]$UsedSubnetsList.Add( $PreviousCidr )
            Write-Output "Added to UsedSubnets list"
         }
         Else
         {
            Write-Output "Not added to UsedSubnets list"
         }
      }
   }
   Else
   {
      Write-Output "No PreviousCidr blocks specified"
   }
   
   $Subnets = Get-AzVirtualNetwork -Name $($Vnet.Name) | Get-AzVirtualNetworkSubnetConfig
   If ($subnets.count -gt 0)
   {
      # Get all used subnets
      ForEach ($Subnet in $Subnets)
      {
         [void]$UsedSubnetsList.Add( $($Subnet.AddressPrefix) )    
      }
     
      # Get all potential subnets based on Desired CIDR passed in
      $candidateSubnets = Split-IPv4Subnet -IPv4Address $VnetAddressSpaceIP -CIDR $VnetAddressSpaceCidr -NewCIDR $DesiredCidr
      Foreach ($candidateSubnet in $candidateSubnets)
      {
         $candidateNetworkID = $candidateSubnet.NetworkID
         $candidateCidr = ( $($candidateNetworkID.IPAddressToString) + "/" + $DesiredCidr)
         [void]$CandidateSubnetsList.Add( $($candidateCidr) ) 
      }

      # Loop through each candidate subnet and remove it if a used subnet overlaps
      Foreach ( $CandidateSubnetsListItem in $CandidateSubnetsList )
      {
         [int]$matched = 0
         Foreach ( $UsedSubnetsListItem in $UsedSubnetsList )
         {
            
            # compare cidrs to see which is smaller, bigger, or equal
            $UsedSubnetsListItemCidr = $UsedSubnetsListItem.split("/")[1]
            $CandidateSubnetsListItemCidr = $CandidateSubnetsListItem.split("/")[1]
            Write-Output "UsedSubnet Cidr: $UsedSubnetsListItemCidr / $UsedSubnetsListItem"
            Write-Output "Candidate Cidr: $CandidateSubnetsListItemCidr / $CandidateSubnetsListItem"
            
            If ( ($UsedSubnetsListItemCidr -as [int]) -lt ($CandidateSubnetsListItemCidr -as [int]) )
            {
               Write-Output "Candidate is smaller"
               $sameSubnet = Test-SubnetMember -SubjectIPAddress $CandidateSubnetsListItem -ObjectIPAddress $UsedSubnetsListItem
               If ( $sameSubnet )
               {
                  Write-Output "Removing Subnet $CandidateSubnetsListItem because $UsedSubnetsListItem is being used ... moving on"
                  $matched += 1
               }
               Else
               {
                  Write-Output "Subnet $UsedSubnetsListItem is NOT inside Network $CandidateSubnetsListItem"
               }
            }
            Elseif (($UsedSubnetsListItemCidr -as [int]) -gt ($CandidateSubnetsListItemCidr -as [int]))
            {
               Write-Output "UsedSubnet is smaller"
               $sameSubnet = Test-SubnetMember -SubjectIPAddress $UsedSubnetsListItem -ObjectIPAddress $CandidateSubnetsListItem
               If ( $sameSubnet )
               {
                  Write-Output "Removing Subnet $CandidateSubnetsListItem because $UsedSubnetsListItem is being used ... moving on"
                  $matched += 1
               }
               Else
               {
                  Write-Output "Subnet $UsedSubnetsListItem is NOT inside Network $CandidateSubnetsListItem"
               }
            }
            Else
            {
               Write-Output "UsedSubnet is EQUAL to candidate ... checking octets"
               
               # compare third octets to see which is smaller, bigger, or equal
               $UsedSubnetsListItemOctet = $UsedSubnetsListItem.split(".")[2]
               $CandidateSubnetsListItemOctet = $CandidateSubnetsListItem.split(".")[2]
               Write-Output "UsedSubnet Octet: $UsedSubnetsListItemOctet / $UsedSubnetsListItem"
               Write-Output "Candidate Octet: $CandidateSubnetsListItemOctet / $CandidateSubnetsListItem"

               If ( ($UsedSubnetsListItemOctet -as [int]) -lt ($CandidateSubnetsListItemOctet -as [int]) )
               {
                  Write-Output "UsedSubnet octet is smaller than Candidate"
                  $sameSubnet = Test-SubnetMember -SubjectIPAddress $CandidateSubnetsListItem -ObjectIPAddress $UsedSubnetsListItem
                  If ( $sameSubnet )
                  {
                     Write-Output "Removing Subnet $CandidateSubnetsListItem because $UsedSubnetsListItem is being used ... moving on"
                     $matched += 1
                  }
                  Else
                  {
                     Write-Output "Subnet $UsedSubnetsListItem is NOT inside Network $CandidateSubnetsListItem"
                  }
               }
               Elseif (($UsedSubnetsListItemOctet -as [int]) -gt ($CandidateSubnetsListItemOctet -as [int]))
               {
                  Write-Output "UsedSubnet octet is larger than Candidate"
                  $sameSubnet = Test-SubnetMember -SubjectIPAddress $UsedSubnetsListItem -ObjectIPAddress $CandidateSubnetsListItem
                  If ( $sameSubnet )
                  {
                     Write-Output "Removing Subnet $CandidateSubnetsListItem because $UsedSubnetsListItem is being used ... moving on"
                     $matched += 1
                  }
                  Else
                  {
                     Write-Output "Subnet $UsedSubnetsListItem is NOT inside Network $CandidateSubnetsListItem"
                  }
                  
               }
               Else
               {
                  Write-Output "UsedSubnet octet and Candidate Octet are EQUAL ... checking one level deeper"

                  # compare third octets to see which is smaller, bigger, or equal
                  $UsedSubnetsListItemOctet = $UsedSubnetsListItem.split(".")[3].Split("/")[0]
                  $CandidateSubnetsListItemOctet = $CandidateSubnetsListItem.split(".")[3].Split("/")[0]
                  Write-Output "UsedSubnet Octet: $UsedSubnetsListItemOctet / $UsedSubnetsListItem"
                  Write-Output "Candidate Octet: $CandidateSubnetsListItemOctet / $CandidateSubnetsListItem"

                  If ( ($UsedSubnetsListItemOctet -as [int]) -lt ($CandidateSubnetsListItemOctet -as [int]) )
                  {
                     Write-Output "UsedSubnet octet is smaller than Candidate"
                     $sameSubnet = Test-SubnetMember -SubjectIPAddress $CandidateSubnetsListItem -ObjectIPAddress $UsedSubnetsListItem
                     If ( $sameSubnet )
                     {
                        Write-Output "Removing Subnet $CandidateSubnetsListItem because $UsedSubnetsListItem is being used ... moving on"
                        $matched += 1
                     }
                     Else
                     {
                        Write-Output "Subnet $UsedSubnetsListItem is NOT inside Network $CandidateSubnetsListItem"
                     }
                  }
                  Elseif (($UsedSubnetsListItemOctet -as [int]) -gt ($CandidateSubnetsListItemOctet -as [int]))
                  {
                     Write-Output "UsedSubnet octet is larger than Candidate"
                     $sameSubnet = Test-SubnetMember -SubjectIPAddress $UsedSubnetsListItem -ObjectIPAddress $CandidateSubnetsListItem
                     If ( $sameSubnet )
                     {
                        Write-Output "Removing Subnet $CandidateSubnetsListItem because $UsedSubnetsListItem is being used ... moving on"
                        $matched += 1
                     }
                     Else
                     {
                        Write-Output "Subnet $UsedSubnetsListItem is NOT inside Network $CandidateSubnetsListItem"
                     }
                     
                  }
                  Else
                  {
                     Write-Output "UsedSubnet octet and Candidate Octet are EQUAL in last octet"
                     $matched += 1
                  }
                  #$matched += 1
               }
            }
         }

         If ( $matched -gt 0 )
         {
            Write-Output "remove $CandidateSubnetsListItem from the list"
         }
         Else
         {
            [void]$SelectedCandidateSubnetList.add($CandidateSubnetsListItem)
         }

         If ( $SelectedCandidateSubnetList.Count -gt 0)
         {
            Break
         }

         [int]$matched = 0
      }
      
      # Return the first one
      $NextAvailCidr = $SelectedCandidateSubnetList[0]

      $jsonResponse = @{
         "details"        = "Subnets have been configured. Providing next CIDR that matches CIDR /$DesiredCidr"
         "proposedCIDR"   = $NextAvailCidr
         "functionInputs" = @{
            SubscriptionID = $SubscriptionID
            VnetRG         = $VnetRG
            VnetName       = $VnetName
            Cidr           = $DesiredCidr
            PreviousCidrs  = $PreviousCidrs
         }
      
      } | ConvertTo-Json -Depth 4
   
      
      Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
            StatusCode = [HttpStatusCode]::OK
            Body       = $jsonResponse   
         })
      Exit 0

   }
   Else
   {
      $NextAvailCidr = ($VnetAddressSpaceIP + "/24")
      
      $jsonResponse = @{
         "details"        = "No subnets configured. Providing a default /24"
         "proposedCIDR"   = $NextAvailCidr
         "functionInputs" = @{
            SubscriptionID = $SubscriptionID
            VnetRG         = $VnetRG
            VnetName       = $VnetName
            Cidr           = $DesiredCidr
            PreviousCidrs  = $PreviousCidrs
         }
      
      } | ConvertTo-Json -Depth 4
   
      
      Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
            StatusCode = [HttpStatusCode]::OK
            Body       = $jsonResponse   
         })
      Exit 0

   }
}
Else
{
   $jsonResponse = @{
      "details"        = "ERROR: No vnet found that matches name $VnetName in Resource Group $VnetRG"
      "proposedCIDR"   = ""
      "functionInputs" = @{
         SubscriptionID = $SubscriptionID
         VnetRG         = $VnetRG
         VnetName       = $VnetName
         Cidr           = $DesiredCidr
         PreviousCidrs  = $PreviousCidrs
      }
   
   } | ConvertTo-Json -Depth 4

   
   Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
         StatusCode = [HttpStatusCode]::OK
         Body       = $jsonResponse   
      })
   Exit 0
}