 function Invoke-PortscanPro
{
<#
.SYNOPSIS

Simple portscan module

PowerSploit Function: Invoke-PortscanPro
Author: Freev (https://github.com/F3eev/Invoke-PortscanPro)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

Does a simple port scan using regular sockets, based (pretty) loosely on nmap

.PARAMETER Hosts

Include these comma seperated hosts (supports IPv4 CIDR notation) or pipe them in

.PARAMETER HostFile

Input hosts from file rather than commandline

.PARAMETER ExcludeHosts

Exclude these comma seperated hosts

.PARAMETER Ports

Include these comma seperated ports (can also be a range like 80-90)

.PARAMETER PortFile

Input ports from a file

.PARAMETER TopPorts

Include the x top ports - only goes to 1000, default is top 50

.PARAMETER ExcludedPorts

Exclude these comma seperated ports

.PARAMETER SkipDiscovery

Treat all hosts as online, skip host discovery

.PARAMETER PingOnly

Ping scan only (disable port scan)

.PARAMETER DiscoveryPorts

Comma separated ports used for host discovery. -1 is a ping

.PARAMETER Threads

number of max threads for the thread pool (per host)

.PARAMETER nHosts

number of hosts to concurrently scan

.PARAMETER Timeout

Timeout time on a connection in miliseconds before port is declared filtered

.PARAMETER SleepTimer

Wait before thread checking, in miliseconds

.PARAMETER SyncFreq

How often (in terms of hosts) to sync threads and flush output

.PARAMETER T

[0-5] shortcut performance options. Default is 3. higher is more aggressive. Sets (nhosts, threads,timeout)
    5 {$nHosts=30;  $Threads = 1000; $Timeout = 750  }
    4 {$nHosts=25;  $Threads = 1000; $Timeout = 1200 }
    3 {$nHosts=20;  $Threads = 100;  $Timeout = 2500 }
    2 {$nHosts=15;  $Threads = 32;   $Timeout = 3000 }
    1 {$nHosts=10;  $Threads = 32;   $Timeout = 5000 }

.PARAMETER GrepOut

Greppable output file

.PARAMETER XmlOut

output XML file

.PARAMETER ReadableOut

output file in 'readable' format

.PARAMETER AllformatsOut

output in readable (.nmap), xml (.xml), and greppable (.gnmap) formats

.PARAMETER noProgressMeter

Suppresses the progress meter

.PARAMETER quiet

supresses returned output and don't store hosts in memory - useful for very large scans

.PARAMETER ForceOverwrite

Force Overwrite if output Files exist. Otherwise it throws exception

.EXAMPLE

C:\PS> Invoke-PortscanPro -Hosts "webstersprodigy.net,google.com,microsoft.com" -TopPorts 50

Description
-----------
Scans the top 50 ports for hosts found for webstersprodigy.net,google.com, and microsoft.com

.EXAMPLE

C:\PS> echo webstersprodigy.net | Invoke-PortscanPro -oG test.gnmap -f -ports "80,443,8080"

Description
-----------
Does a portscan of "webstersprodigy.net", and writes a greppable output file

.EXAMPLE

C:\PS> Invoke-PortscanPro -Hosts 192.168.1.1/24 -T 4 -TopPorts 25 -oA localnet
Description
-----------
Scans the top 20 ports for hosts found in the 192.168.1.1/24 range, outputs all file formats

.LINK
C:\PS> Invoke-PortscanPro -Hosts 192.168.1.1/24 -ports {80,8080} -sports {8011,8080} 
C:\PS> Invoke-PortscanPro -Hosts 192.168.1.1/24 -ports {80,8080} -sports *
C:\PS> Invoke-PortscanPro -Hosts 192.168.1.1/24 -ports {80,8080} -sports 80
Description
Identify Scan Port (sports) 
http://webstersprodigy.net
#>

    [CmdletBinding()]Param (
        #Host, Ports
        [Parameter(ParameterSetName="cmdHosts",

                   ValueFromPipeline=$True,
                   Mandatory = $True)]
                   [String[]] $Hosts,

        [Parameter(ParameterSetName="fHosts",
                   Mandatory = $True)]
                   [Alias("iL")]
                   [String]  $HostFile,

        [Parameter(Mandatory = $False)]
                   [Alias("exclude")]
                   [String] $ExcludeHosts,

        [Parameter(Mandatory = $False)]
                   [Alias("p")]
                   [String] $Ports,

        [Parameter(Mandatory = $False)]
                   [Alias("iP")]
                   [String] $PortFile,

        [Parameter(Mandatory = $False)]
                   [String] $TopPorts,

        [Parameter(Mandatory = $False)]
                   [Alias("xPorts")]
                   [String] $ExcludedPorts,

        #Host Discovery
        [Parameter(Mandatory = $False)]
                   [Alias("Pn")]
                   [Switch] $SkipDiscovery,

        [Parameter(Mandatory = $False)]
                   [Alias("sn")]
                   [Switch] $PingOnly,

        [Parameter(Mandatory = $False)]
                   [Alias("PS")]
                   [string] $DiscoveryPorts = "-1,445,80,443",

        #Get Port Info
         [Parameter(Mandatory = $False)]
                  
                   [String] $Sports,

        #Timing and Performance
        [Parameter(Mandatory = $False)]
                   [int] $Threads = 100,

        [Parameter(Mandatory = $False)]
                   [int] $nHosts = 25,

        [Parameter(Mandatory = $False)]
                   [int] $Timeout = 2000,

        [Parameter(Mandatory = $False)]
                   [int] $SleepTimer = 500,

        [Parameter(Mandatory = $False)]
                   [int] $SyncFreq = 1024,

        [Parameter(Mandatory = $False)]
                   [int] $T,

        #Output
        [Parameter(Mandatory = $False)]
                   [Alias("oG")]
                   [String] $GrepOut,

        [Parameter(Mandatory = $False)]
                   [Alias("oX")]
                   [String] $XmlOut,

        [Parameter(Mandatory = $False)]
                   [Alias("oN")]
                   [String] $ReadableOut,

        [Parameter(Mandatory = $False)]
                   [Alias("oA")]
                   [String] $AllformatsOut,

        [Parameter(Mandatory = $False)]
                   [Switch] $noProgressMeter,

        [Parameter(Mandatory = $False)]
                   [Alias("q")]
                   [Switch] $quiet,

        [Parameter(Mandatory = $False)]
                   [Alias("F")]
                   [Switch] $ForceOverwrite

       

        #TODO add script parameter
        #TODO add resume parameter
    )

    PROCESS {

        Set-StrictMode -Version 2.0

        $version = .13
        $hostList = New-Object System.Collections.ArrayList
        $portList = New-Object System.Collections.ArrayList
        $hostPortList = New-Object System.Collections.ArrayList

        $scannedHostList = @()

        function Parse-Hosts
        {
            Param (
                [Parameter(Mandatory = $True)] [String] $Hosts
            )

            [String[]] $iHosts = $Hosts.Split(",")

            foreach($iHost in $iHosts)
            {
                $iHost = $iHost.Replace(" ", "")

                if(!$iHost)
                {
                    continue
                }

                if($iHost.contains("/"))
                {
                    $netPart = $iHost.split("/")[0]
                    [uint32]$maskPart = $iHost.split("/")[1]

                    $address = [System.Net.IPAddress]::Parse($netPart)

                    if ($maskPart -ge $address.GetAddressBytes().Length * 8)
                    {
                        throw "Bad host mask"
                    }

                    $numhosts = [System.math]::Pow(2,(($address.GetAddressBytes().Length *8) - $maskPart))

                    $startaddress = $address.GetAddressBytes()
                    [array]::Reverse($startaddress)

                    $startaddress = [System.BitConverter]::ToUInt32($startaddress, 0)
                    [uint32]$startMask = ([System.math]::Pow(2, $maskPart)-1) * ([System.Math]::Pow(2,(32 - $maskPart)))
                    $startAddress = $startAddress -band $startMask

                    #in powershell 2.0 there are 4 0 bytes padded, so the [0..3] is necessary
                    $startAddress = [System.BitConverter]::GetBytes($startaddress)[0..3]
                    [array]::Reverse($startaddress)

                    $address = [System.Net.IPAddress] [byte[]] $startAddress

                    $hostList.Add($address.IPAddressToString)

                    for ($i=0; $i -lt $numhosts-1; $i++)
                    {

                        $nextAddress =  $address.GetAddressBytes()
                        [array]::Reverse($nextAddress)
                        $nextAddress =  [System.BitConverter]::ToUInt32($nextAddress, 0)
                        $nextAddress ++
                        $nextAddress = [System.BitConverter]::GetBytes($nextAddress)[0..3]
                        [array]::Reverse($nextAddress)

                        $address = [System.Net.IPAddress] [byte[]] $nextAddress
                        $hostList.Add($address.IPAddressToString)

                    }

                }
                else
                {
                    $hostList.Add($iHost)
                }
            }
        }

        function Parse-ILHosts
        {
           Param (
                [Parameter(Mandatory = $True)] [String] $HostFile
            )

            Get-Content $HostFile | ForEach-Object {
                Parse-Hosts $_
            }
        }

        function Exclude-Hosts
        {
            Param (
                [Parameter(Mandatory = $True)] [String] $excludeHosts
            )

            [String[]] $iHosts = $excludeHosts.Split(",")

            foreach($iHost in $iHosts)
            {
                $iHost = $iHost.Replace(" ", "")
                $hostList.Remove($iHost)
            }
        }

        function Get-TopPort
        {
            Param (
                [Parameter(Mandatory = $True)]
                [ValidateRange(1,1000)]
                [int] $numPorts
            )

            #list of top 1000 ports from nmap from Jun 2013
            [int[]] $topPortList = @(80,23,443,21,3389,110,445,139,143,53,135,3306,8080,22
                        1723,111,995,993,5900,1025,1720,548,113,81,6001,179,1026,2000,8443,
                        8000,32768,554,26,1433,49152,2001,515,8008,49154,1027,5666,646,5000,
                        5631,631,49153,8081,2049,88,79,5800,106,2121,1110,49155,6000,513,
                        990,5357,49156,543,544,5101,144,7,389,8009,9999,5009,7070,5190,3000,
                        5432,1900,3986,13,1029,9,5051,6646,49157,1028,873,1755,2717,4899,9100,
                        119,37,1000,3001,5001,82,10010,1030,9090,2107,1024,2103,6004,1801,
                        5050,19,8031,1041,255,1048,1049,1053,1054,1056,1064,3703,17,808,3689,
                        1031,1044,1071,5901,100,9102,2869,4001,5120,8010,9000,2105,636,1038,
                        2601,1,7000,1066,1069,625,311,280,254,4000,1761,5003,2002,1998,2005,
                        1032,1050,6112,1521,2161,6002,2401,902,4045,787,7937,1058,2383,1033,
                        1040,1059,50000,5555,1494,3,593,2301,3268,7938,1022,1234,1035,1036,1037,
                        1074,8002,9001,464,497,1935,2003,6666,6543,24,1352,3269,1111,407,500,
                        20,2006,1034,1218,3260,15000,4444,264,33,2004,1042,42510,999,3052,1023,
                        222,1068,888,7100,1717,992,2008,7001,2007,8082,512,1043,2009,5801,1700,
                        7019,50001,4662,2065,42,2602,3333,9535,5100,2604,4002,5002,1047,1051,1052,
                        1055,1060,1062,1311,3283,4443,5225,5226,6059,6789,8089,8651,8652,8701,9415,
                        9593,9594,9595,16992,16993,20828,23502,32769,33354,35500,52869,55555,55600,
                        64623,64680,65000,65389,1067,13782,366,5902,9050,85,1002,5500,1863,1864,
                        5431,8085,10243,45100,49999,51103,49,90,6667,1503,6881,27000,340,1500,8021,
                        2222,5566,8088,8899,9071,5102,6005,9101,163,5679,146,648,1666,83,3476,5004,
                        5214,8001,8083,8084,9207,14238,30,912,12345,2030,2605,6,541,4,1248,3005,8007,
                        306,880,2500,1086,1088,2525,4242,8291,9009,52822,900,6101,2809,7200,211,800,
                        987,1083,12000,705,711,20005,6969,13783,1045,1046,1061,1063,1070,1072,1073,
                        1075,1077,1078,1079,1081,1082,1085,1093,1094,1096,1098,1099,1100,1104,1106,
                        1107,1108,1148,1169,1272,1310,1687,1718,1783,1840,2100,2119,2135,2144,2160,
                        2190,2260,2381,2399,2492,2607,2718,2811,2875,3017,3031,3071,3211,3300,3301,
                        3323,3325,3351,3404,3551,3580,3659,3766,3784,3801,3827,3998,4003,4126,4129,
                        4449,5222,5269,5633,5718,5810,5825,5877,5910,5911,5925,5959,5960,5961,5962,
                        5987,5988,5989,6123,6129,6156,6389,6580,6901,7106,7625,7777,7778,7911,8086,
                        8181,8222,8333,8400,8402,8600,8649,8873,8994,9002,9011,9080,9220,9290,9485,
                        9500,9502,9503,9618,9900,9968,10002,10012,10024,10025,10566,10616,10617,10621,
                        10626,10628,10629,11110,13456,14442,15002,15003,15660,16001,16016,16018,17988,
                        19101,19801,19842,20000,20031,20221,20222,21571,22939,24800,25734,27715,28201,
                        30000,30718,31038,32781,32782,33899,34571,34572,34573,40193,48080,49158,49159,
                        49160,50003,50006,50800,57294,58080,60020,63331,65129,691,212,1001,1999,2020,
                        2998,6003,7002,50002,32,2033,3372,99,425,749,5903,43,458,5405,6106,6502,7007,
                        13722,1087,1089,1124,1152,1183,1186,1247,1296,1334,1580,1782,2126,2179,2191,2251,
                        2522,3011,3030,3077,3261,3493,3546,3737,3828,3871,3880,3918,3995,4006,4111,4446,
                        5054,5200,5280,5298,5822,5859,5904,5915,5922,5963,7103,7402,7435,7443,7512,8011,
                        8090,8100,8180,8254,8500,8654,9091,9110,9666,9877,9943,9944,9998,10004,10778,15742,
                        16012,18988,19283,19315,19780,24444,27352,27353,27355,32784,49163,49165,49175,
                        50389,50636,51493,55055,56738,61532,61900,62078,1021,9040,666,700,84,545,1112,
                        1524,2040,4321,5802,38292,49400,1084,1600,2048,2111,3006,6547,6699,9111,16080,
                        555,667,720,801,1443,1533,2106,5560,6007,1090,1091,1114,1117,1119,1122,1131,1138,
                        1151,1175,1199,1201,1271,1862,2323,2393,2394,2608,2725,2909,3003,3168,3221,3322,
                        3324,3390,3517,3527,3800,3809,3814,3826,3869,3878,3889,3905,3914,3920,3945,3971,
                        4004,4005,4279,4445,4550,4567,4848,4900,5033,5080,5087,5221,5440,5544,5678,5730,
                        5811,5815,5850,5862,5906,5907,5950,5952,6025,6510,6565,6567,6689,6692,6779,6792,
                        6839,7025,7496,7676,7800,7920,7921,7999,8022,8042,8045,8093,8099,8200,8290,8292,
                        8300,8383,9003,9081,9099,9200,9418,9575,9878,9898,9917,10003,10180,10215,11111,
                        12174,12265,14441,15004,16000,16113,17877,18040,18101,19350,25735,26214,27356,
                        30951,32783,32785,40911,41511,44176,44501,49161,49167,49176,50300,50500,52673,
                        52848,54045,54328,55056,56737,57797,60443,70,417,714,722,777,981,1009,2022,4224,
                        4998,6346,301,524,668,765,2041,5999,10082,259,1007,1417,1434,1984,2038,2068,4343,
                        6009,7004,44443,109,687,726,911,1461,2035,4125,6006,7201,9103,125,481,683,903,
                        1011,1455,2013,2043,2047,6668,6669,256,406,843,2042,2045,5998,9929,31337,44442,
                        1092,1095,1102,1105,1113,1121,1123,1126,1130,1132,1137,1141,1145,1147,1149,1154,
                        1164,1165,1166,1174,1185,1187,1192,1198,1213,1216,1217,1233,1236,1244,1259,1277,
                        1287,1300,1301,1309,1322,1328,1556,1641,1688,1719,1721,1805,1812,1839,1875,1914,
                        1971,1972,1974,2099,2170,2196,2200,2288,2366,2382,2557,2800,2910,2920,2968,3007,
                        3013,3050,3119,3304,3307,3376,3400,3410,3514,3684,3697,3700,3824,3846,3848,3859,
                        3863,3870,3872,3888,3907,3916,3931,3941,3957,3963,3968,3969,3972,3990,3993,3994,
                        4009,4040,4080,4096,4143,4147,4200,4252,4430,4555,4600,4658,4875,4949,5040,5063,
                        5074,5151,5212,5223,5242,5279,5339,5353,5501,5807,5812,5818,5823,5868,5869,5899,
                        5905,5909,5914,5918,5938,5940,5968,5981,6051,6060,6068,6203,6247,6500,6504,6520,
                        6550,6600)
            $numPorts--
            $portList.AddRange($topPortList[0..$numPorts])
        }

        function Parse-Ports
        {
            Param (
                [Parameter(Mandatory = $True)] [String] $Ports,
                [Parameter(Mandatory = $True)] $pList
            )

            foreach ($pRange in $Ports.Split(","))
            {

                #-1 is a special case for ping
                if ($pRange -eq "-1")
                {
                    $pList.Add([int]$pRange)
                }
                elseif ($pRange.Contains("-"))
                {
                    [int[]] $range = $pRange.Split("-")
                    if ($range.Count -ne 2 -or $pRange.Split("-")[0] -eq "" -or $pRange.split("-")[1] -eq "")
                    {
                        throw "Invalid port range"
                    }

                    $pList.AddRange($range[0]..$range[1])
                }
                else
                {
                    $pList.Add([int]$pRange)
                }

            }
            foreach ($p in $pList)
            {
                if ($p -lt -1 -or $p -gt 65535)
                {
                    throw "Port $p out of range"
                }
            }
         }

        function Parse-IpPorts
        {
           Param (
                [Parameter(Mandatory = $True)] [String] $PortFile
            )

            Get-Content $PortFile | ForEach-Object {
                Parse-Ports -Ports $_ -pList $portList
            }
        }

        function Remove-Ports
        {
            Param (
                [Parameter(Mandatory = $True)] [string] $ExcludedPorts
            )

            [int[]] $ExcludedPorts = $ExcludedPorts.Split(",")

            foreach ($x in $ExcludedPorts)
            {
                $portList.Remove($x)
            }
        }

        function Write-PortscanOut
        {
            Param (
                [Parameter(Mandatory = $True, ParameterSetName="Comment")] [string] $comment,
                [Parameter(Mandatory = $True, ParameterSetName="HostOut")] [string] $outhost,
                [Parameter(Mandatory = $True, ParameterSetName="HostOut")] [bool] $isUp,
                [Parameter(Mandatory = $True, ParameterSetName="HostOut")] $openPorts,
                [Parameter(Mandatory = $True, ParameterSetName="HostOut")] $closedPorts,
                [Parameter(Mandatory = $True, ParameterSetName="HostOut")] $filteredPorts,
                [Parameter()] [bool] $SkipDiscovery,
                [Parameter()] [System.IO.StreamWriter] $grepStream,
                [Parameter()] [System.Xml.XmlWriter] $xmlStream,
                [Parameter()] [System.IO.StreamWriter] $readableStream

            )
            switch ($PSCmdlet.ParameterSetName)
            {
                "Comment"
                {

                    Write-Verbose $comment

                    if ($grepStream) {
                        $grepStream.WriteLine("# " + $comment)
                    }
                    if ($xmlStream) {
                        $xmlStream.WriteComment($comment)
                    }
                    if ($readableStream) {
                        $readableStream.WriteLine($comment)
                    }
                }
                "HostOut"
                {
                    $oPort = [string]::join(",", $openPorts.ToArray())
                    $cPort = [string]::join(",", $closedPorts.ToArray())
                    $fPort = [string]::join(",", $filteredPorts.ToArray())

                    if ($grepStream) {
                       #for grepstream use tabs - can be ugly, but easier for regex
                       if ($isUp -and !$SkipDiscovery) {
                            $grepStream.writeline("Host: $outhost`tStatus: Up")
                        }
                        if ($isUp -or $SkipDiscovery) {
                            if ($oPort -ne "") {
                                $grepStream.writeline("Host: $outhost`tOpen Ports: $oPort")
                            }
                            if ($cPort -ne "") {
                                $grepStream.writeline("Host: $outhost`tClosed Ports: $cPort")
                            }
                            if ($fPort -ne "") {
                                $grepStream.writeline("Host: $outhost`tFiltered Ports: $fPort")
                            }
                        }
                        elseif (!$SkipDiscovery) {
                            $grepStream.writeline("Host: $outhost`tStatus: Down")
                        }
                    }
                    if ($xmlStream) {
                        $xmlStream.WriteStartElement("Host")

                        $xmlStream.WriteAttributeString("id", $outhost)
                        if (!$SkipDiscovery) {
                            if ($isUp) {
                                $xmlStream.WriteAttributeString("Status", "Up")
                             }
                             else {
                                $xmlStream.WriteAttributeString("Status", "Downs")
                             }
                        }

                        $xmlStream.WriteStartElement("Ports")
                        foreach($p in $openPorts) {
                            $xmlStream.writestartElement("Port")
                            $xmlStream.WriteAttributeString("id", [string]$p)
                            $xmlStream.WriteAttributeString("state", "open")
                            $xmlStream.WriteEndElement()

                        }
                        foreach ($p in $closedPorts) {
                            $xmlStream.writestartElement("Port")
                            $xmlStream.WriteAttributeString("id", [string]$p)
                            $xmlStream.WriteAttributeString("state", "closed")
                            $xmlStream.WriteEndElement()
                        }
                        foreach ($p in $filteredPorts) {
                            $xmlStream.writestartElement("Port")
                            $xmlStream.WriteAttributeString("id", [string]$p)
                            $xmlStream.WriteAttributeString("state", "filtered")
                            $xmlStream.WriteEndElement()
                        }

                        $xmlStream.WriteEndElement()
                        $xmlStream.WriteEndElement()
                    }
                    if ($readableStream) {
                        $readableStream.writeline("Porscan.ps1 scan report for $outhost")
                        if ($isUp) {
                            $readableStream.writeline("Host is up")
                        }

                        if ($isUp -or $SkipDiscovery) {

                            $readableStream.writeline(("{0,-10}{1,0}" -f "PORT", "STATE"))

                            [int[]]$allports = $openPorts + $closedPorts + $filteredPorts
                            foreach($p in ($allports| Sort-Object))
                            {
                                if ($openPorts.Contains($p)) {
                                    $readableStream.writeline(("{0,-10}{1,0}" -f $p, "open"))
                                }
                                elseif ($closedPorts.Contains($p)) {
                                    $readableStream.writeline(("{0,-10}{1,0}" -f $p, "closed"))
                                }
                                elseif ($filteredPorts.Contains($p)) {
                                    $readableStream.writeline(("{0,-10}{1,0}" -f $p, "filtered"))
                                }
                            }

                        }
                        elseif(!$SkipDiscovery) {
                            $readableStream.writeline("Host is Down")
                        }
                        $readableStream.writeline("")
                    }
                }
            }
        }

        #function for Powershell v2.0 to work
        function Convert-SwitchtoBool
        {
            Param (
                [Parameter(Mandatory = $True)] $switchValue
            )
            If ($switchValue) {
                return $True
            }
            return $False
        }

        try
        {

            [bool] $SkipDiscovery = Convert-SwitchtoBool ($SkipDiscovery)
            [bool] $PingOnly = Convert-SwitchtoBool ($PingOnly)
            [bool] $quiet  = Convert-SwitchtoBool ($quiet)
            [bool] $ForceOverwrite  = Convert-SwitchtoBool ($ForceOverwrite)

            #########
            #parse arguments
            #########

            [Environment]::CurrentDirectory=(Get-Location -PSProvider FileSystem).ProviderPath

            if ($PsCmdlet.ParameterSetName -eq "cmdHosts")
            {
                foreach($h in $Hosts)
                {
                    Parse-Hosts($h) | Out-Null
                }
            }
            else
            {
                Parse-ILHosts($HostFile) | Out-Null
            }
            if($ExcludeHosts)
            {
                Exclude-Hosts($ExcludeHosts)
            }
            if (($TopPorts -and $Ports) -or ($TopPorts -and $PortFile))
            {
                throw "Cannot set topPorts with other specific ports"
            }
            if($Ports)
            {
                Parse-Ports -Ports $Ports -pList $portList | Out-Null
            }
            if($PortFile)
            {
                Parse-IpPorts($PortFile) | Out-Null
            }
            if($portList.Count -eq 0)
            {
                if ($TopPorts)
                {
                    Get-TopPort($TopPorts) | Out-Null
                }
                else
                {
                    #if the ports still aren't set, give the deftault, top 50 ports
                    Get-TopPort(50) | Out-Null
                }
            }
            if ($ExcludedPorts)
            {
                Remove-Ports -ExcludedPorts $ExcludedPorts | Out-Null
            }

            if($T)
            {
                switch ($T)
                {
                    5 {$nHosts=30;  $Threads = 1000; $Timeout = 750 }
                    4 {$nHosts=25;  $Threads = 1000; $Timeout = 1200 }
                    3 {$nHosts=20;  $Threads = 100;  $Timeout = 2500 }
                    2 {$nHosts=15;  $Threads = 32;   $Timeout = 3000 }
                    1 {$nHosts=10;  $Threads = 32;   $Timeout = 5000 }
                    default {
                        throw "Invalid T parameter"
                    }
                }
            }

            $grepStream = $null
            $xmlStream = $null
            $readableStream = $null

            if($AllformatsOut)
            {
                if ($GrepOut -or $XmlOut -or $ReadableOut) {
                     Write-Warning "Both -oA specified with other output... going to ignore -oG/-oN/-oX"
                }
                $GrepOut = $AllformatsOut + ".gnmap"
                $XmlOut = $AllformatsOut + ".xml"
                $ReadableOut = $AllformatsOut + ".nmap"
            }
            if ($GrepOut) {
                if (!$ForceOverwrite -and (Test-Path $GrepOut)) {
                    throw "Error: $AllformatsOut already exists. Either delete the file or specify the -f flag"
                }
                $grepStream = [System.IO.StreamWriter] $GrepOut
            }
            if ($ReadableOut) {
                if (!$ForceOverwrite -and (Test-Path $ReadableOut)) {
                    throw "Error: $ReadableOut already exists. Either delete the file or specify the -f flag"
                }
                $readableStream = [System.IO.StreamWriter] $ReadableOut
            }
            if ($XmlOut) {
                if (!$ForceOverwrite -and (Test-Path $XmlOut)) {
                    throw "Error: $XmlOut already exists. Either delete the file or specify the -f flag"
                }

                $xmlStream =   [System.xml.xmlwriter]::Create([string]$XmlOut)
                $xmlStream.WriteStartDocument()
                $xmlStream.WriteStartElement("Portscanrun")
                $xmlStream.WriteAttributeString("version", $version)

            }

            Parse-Ports -Ports $DiscoveryPorts -pList $hostPortList | Out-Null

            $startdate = Get-Date
            $myInvocationLine = $PSCmdlet.MyInvocation.Line
            $startMsg = "Invoke-PortscanPro.ps1 v$version scan initiated $startdate as: $myInvocationLine"

            #TODO deal with output
            Write-PortscanOut -comment $startMsg -grepStream $grepStream -xmlStream $xmlStream -readableStream $readableStream

            #converting back from int array gives some argument error checking
            $sPortList = [string]::join(",", $portList)
            $sHostPortList = [string]::join(",", $hostPortList)

            ########
            #Port Scan Code - run on a per host basis
            ########
            $portScanCode = {
                param (
                    [Parameter( Mandatory = $True)] [string] $thost,
                    [Parameter( Mandatory = $True)][bool] $SkipDiscovery,
                    [Parameter( Mandatory = $True)][bool] $PingOnly,
                    [Parameter( Mandatory = $True)][int] $Timeout,
                    [Parameter( Mandatory = $True)] $PortList,
                    [Parameter( Mandatory = $True)] $hostPortList,
                    [Parameter( Mandatory = $True)][int] $maxthreads,
                    [Parameter( Mandatory = $False)] $SPortsList
                    )
                Process
                {
                $openPorts = New-Object System.Collections.ArrayList
                $closedPorts = New-Object System.Collections.ArrayList
                $filteredPorts = New-Object System.Collections.ArrayList

                $sockets = @{}
                $timeouts = New-Object Hashtable
                
                #set maximum $async threads
                $fThreads = New-Object int
                $aThreads = New-Object int
                [System.Threading.ThreadPool]::GetMaxThreads([ref]$fThreads, [ref]$aThreads) | Out-Null
                [System.Threading.ThreadPool]::SetMaxThreads($fthreads,$maxthreads) | Out-Null

                function New-ScriptBlockCallback {
                    param(
                        [parameter(Mandatory=$true)]
                        [ValidateNotNullOrEmpty()]
                        [scriptblock]$Callback
                    )

                    #taken from http://www.nivot.org/blog/post/2009/10/09/PowerShell20AsynchronousCallbacksFromNET
                    if (-not ("CallbackEventBridge" -as [type])) {
                        Add-Type @"
                            using System;

                            public sealed class CallbackEventBridge
                            {
                                public event AsyncCallback CallbackComplete = delegate { };

                                private CallbackEventBridge() {}

                                private void CallbackInternal(IAsyncResult result)
                                {
                                    CallbackComplete(result);
                                }

                                public AsyncCallback Callback
                                {
                                    get { return new AsyncCallback(CallbackInternal); }
                                }

                                public static CallbackEventBridge Create()
                                {
                                    return new CallbackEventBridge();
                                }
                            }
"@
                    }

                    $bridge = [CallbackEventBridge]::Create()
                    Register-ObjectEvent -InputObject $bridge -EventName CallbackComplete -Action $Callback | Out-Null

                    $bridge.Callback

                }

                # my pro main code

                function GetOutput 
                { 
                    $buffer = new-object System.Byte[] 1024 
                    $encoding = new-object System.Text.AsciiEncoding 
                    $outputBuffer = "" 
                    $findMore = $false 
                    do{ 
                        start-sleep -m 100 
                        $findmore = $false 
                        $stream.ReadTimeout = 100 
                        do{ 
                            try { 
                                $read = $stream.Read($buffer, 0, 1024) 
                                if($read -gt 0){ 
                                    $findmore = $true 
                                    $outputBuffer += ($encoding.GetString($buffer, 0, $read)) 
                                } 
                            } catch { $findMore = $false; $read = 0 } 
                        } while($read -gt 0) 
                    } while($findmore) 
                    $outputBuffer 
                }
                # Distinguish service 
                function DisService() {
                    param
                    (
                        $ip,
                        $port,
                        $output
                    )
                    
                    $Signs =
                        'http|^HTTP.*',
                        'http|^HTTP/0.',
                        'http|^HTTP/1.',
                        'http|<HEAD>.*<BODY>',
                        'http|<HTML>.*',
                        'http|<html>.*',
                        'http|<!DOCTYPE.*',
                        'http|^Invalid requested URL ',
                        'http|.*<?xml',
                        'http|^HTTP/.*\nServer: Apache/1',
                        'http|^HTTP/.*\nServer: Apache/2',
                        'http|.*Microsoft-IIS.*',
                        'http|.*<title>.*',
                        'http|^HTTP/.*\nServer: Microsoft-IIS',
                        'http|^HTTP/.*Cookie.*ASPSESSIONID',
                        'http|^<h1>Bad Request .Invalid URL.</h1>',
                        'http-jserv|^HTTP/.*Cookie.*JServSessionId',
                        'http-weblogic|^HTTP/.*Cookie.*WebLogicSession',
                        'http-vnc|^HTTP/.*VNC desktop',
                        'http-vnc|^HTTP/.*RealVNC/',
                        'redis|^-ERR',
                        'mongodb|^.*version.....([\.\d]+)',
                        'pop3|.*POP3.*',
                        'pop3|.*pop3.*',
                        'ssh|SSH-2.0-OpenSSH.*',
                        'ssh|SSH-1.0-OpenSSH.*',
                        'ssh|.*ssh.*',
                        'netbios|^\x79\x08.*BROWSE',
                        'netbios|^\x79\x08.\x00\x00\x00\x00',
                        'netbios|^\x05\x00\x0d\x03',
                        'netbios|^\x83\x00',
                        'netbios|^\x82\x00\x00\x00',
                        'netbios|\x83\x00\x00\x01\x8f',
                        'backdoor-fxsvc|^500 Not Loged in',
                        'backdoor-shell|GET: command',
                        'backdoor-shell|sh: GET:',
                        'bachdoor-shell|[a-z]*sh: .* command not found',
                        'backdoor-shell|^bash[$#]',
                        'backdoor-shell|^sh[$#]',
                        'backdoor-cmdshell|^Microsoft Windows .* Copyright .*>',
                        'dell-openmanage|^\x4e\x00\x0d',
                        'finger|^\r\n	Line	  User',
                        'finger|Line	 User',
                        'finger|Login name: ',
                        'finger|Login.*Name.*TTY.*Idle',
                        'finger|^No one logged on',
                        'finger|^\r\nWelcome',
                        'finger|^finger:',
                        'finger|^must provide username',
                        'finger|finger: GET: ',
                        'ftp|^220.*\n331',
                        'ftp|^220.*\n530',
                        'ftp|^220.*FTP',
                        'ftp|^220 .* Microsoft .* FTP',
                        'ftp|^220 Inactivity timer',
                        'ftp|^220 .* UserGate',
                        'ftp|^220(.*?)',
                        'ldap|^\x30\x0c\x02\x01\x01\x61',
                        'ldap|^\x30\x32\x02\x01',
                        'ldap|^\x30\x33\x02\x01',
                        'ldap|^\x30\x38\x02\x01',
                        'ldap|^\x30\x84',
                        'ldap|^\x30\x45',
                        'ldap|^\x30.*',
                        'smb|^\0\0\0.\xffSMBr\0\0\0\0.*',
                        'msrdp|^\x03\x00\x00\x0b',
                        'msrdp|^\x03\x00\x00\x11',
                        'msrdp|^\x03\0\0\x0b\x06\xd0\0\0\x12.\0$',
                        'msrdp|^\x03\0\0\x17\x08\x02\0\0Z~\0\x0b\x05\x05@\x06\0\x08\x91J\0\x02X$',
                        'msrdp|^\x03\0\0\x11\x08\x02..}\x08\x03\0\0\xdf\x14\x01\x01$',
                        'msrdp|^\x03\0\0\x0b\x06\xd0\0\0\x03.\0$',
                        'msrdp|^\x03\0\0\x0b\x06\xd0\0\0\0\0\0',
                        'msrdp|^\x03\0\0\x0e\t\xd0\0\0\0[\x02\xa1]\0\xc0\x01\n$',
                        'msrdp|^\x03\0\0\x0b\x06\xd0\0\x004\x12\0',
                        'msrdp-proxy|^nmproxy: Procotol byte is not 8\n$',
                        'msrpc|^\x05\x00\x0d\x03\x10\x00\x00\x00\x18\x00\x00\x00\x00\x00',
                        'msrpc|\x05\0\r\x03\x10\0\0\0\x18\0\0\0....\x04\0\x01\x05\0\0\0\0$',
                        'mssql|^\x04\x01\0C..\0\0\xaa\0\0\0/\x0f\xa2\x01\x0e.*',
                        'mssql|^\x05\x6e\x00',
                        'mssql|^\x04\x01\x00\x25\x00\x00\x01\x00\x00\x00\x15.*',
                        'mssql|^\x04\x01\x00.\x00\x00\x01\x00\x00\x00\x15.*',
                        'mssql|^\x04\x01\x00\x25\x00\x00\x01\x00\x00\x00\x15.*',
                        'mssql|^\x04\x01\x00.\x00\x00\x01\x00\x00\x00\x15.*',
                        'mssql|^\x04\x01\0\x25\0\0\x01\0\0\0\x15\0\x06\x01.*',
                        'mssql|^\x04\x01\x00\x25\x00\x00\x01.*',
                        'mysql|^\x19\x00\x00\x00\x0a',
                        'mysql|^\x2c\x00\x00\x00\x0a',
                        "mysql|hhost \'",
                        "mysql|khost \'",
                        'mysql|mysqladmin',
                        'mysql|(.*)5(.*)log',
                        'mysql|(.*)4(.*)log',
                        "mysql|whost \'",
                        'mysql|^\(\x00\x00',
                        'mysql|this MySQL',
                        'mysql|^N\x00',
                        'mysql|(.*)mysql(.*)',
                        'mssql|;MSSQLSERVER;',
                        'nagiosd|Sorry, you \(.*are not among the allowed hosts...',
                        'nessus|< NTP 1.2 >\x0aUser:',
                        'oracle|\(ERROR_STACK=\(ERROR=\(CODE=',
                        'oracle|\(ADDRESS=\(PROTOCOL=',
                        'oracle-dbsnmp|^\x00\x0c\x00\x00\x04\x00\x00\x00\x00',
                        'oracle-https|^220- ora',
                        'oracle-rmi|\x00\x00\x00\x76\x49\x6e\x76\x61',
                        'oracle-rmi|^\x4e\x00\x09',
                        'postgres|Invalid packet length',
                        'postgres|^EFATAL',
                        'rlogin|login: ',
                        'rlogin|rlogind: ',
                        'rlogin|^\x01\x50\x65\x72\x6d\x69\x73\x73\x69\x6f\x6e\x20\x64\x65\x6e\x69\x65\x64\x2e\x0a',
                        'rpc-nfs|^\x02\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00',
                        'rpc|\x01\x86\xa0',
                        'rpc|\x03\x9b\x65\x42\x00\x00\x00\x01',
                        'rpc|^\x80\x00\x00',
                        'rsync|^@RSYNCD:.*',
                        'smux|^\x41\x01\x02\x00',
                        'snmp|\x70\x75\x62\x6c\x69\x63\xa2',
                        'snmp|\x41\x01\x02',
                        'socks|^\x05[\x00-\x08]\x00',
                        'ssh|^SSH-',
                        'ssh|^SSH-.*openssh',
                        'sybase|^\x04\x01\x00',
                        'telnet|^\xff\xfd',
                        'telnet-disabled|Telnet is disabled now',
                        'telnet|^\xff\xfe',
                        'telnet|^xff\xfb\x01\xff\xfb\x03\xff\xfb\0\xff\xfd.*',
                        'tftp|^\x00[\x03\x05]\x00',
                        'uucp|^login: password: ',
                        'vnc|^RFB.*',
                        'webmin|.*MiniServ',
                        'RMI|^N.*',
                        'webmin|^0\.0\.0\.0:.*:[0-9]',
                        'websphere-javaw|^\x15\x00\x00\x00\x02\x02\x0a',
                        'db2|.*SQLDB2RA'
                    foreach ($sign in $Signs) {
                        if ($output -match ($sign -Split "\|")[1]) {
                            return $ip , $port , ($sign -Split "\|")[0]
                        }
                    }
                    return $ip , $port , $False
                }
                # get service 
                function GetService
                {

                    Param (
                        $thost,
                        $port
                    )
                    $putData =
                        '\r\n\r\n',
                        'GET / HTTP/1.0\r\n\r\n',
                        'GET / \r\n\r\n',
                        '\x01\x00\x00\x00\x01\x00\x00\x00\x08\x08',
                        '\x80\0\0\x28\x72\xFE\x1D\x13\0\0\0\0\0\0\0\x02\0\x01\x86\xA0\0\x01\x97\x7C\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0',
                        '\x03\0\0\x0b\x06\xe0\0\0\0\0\0',
                        '\0\0\0\xa4\xff\x53\x4d\x42\x72\0\0\0\0\x08\x01\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x40\x06\0\0\x01\0\0\x81\0\x02PC NETWORK PROGRAM 1.0\0\x02MICROSOFT NETWORKS 1.03\0\x02MICROSOFT NETWORKS 3.0\0\x02LANMAN1.0\0\x02LM1.2X002\0\x02Samba\0\x02NT LANMAN 1.0\0\x02NT LM 0.12\0',
                        '\x80\x9e\x01\x03\x01\x00u\x00\x00\x00 \x00\x00f\x00\x00e\x00\x00d\x00\x00c\x00\x00b\x00\x00:\x00\x009\x00\x008\x00\x005\x00\x004\x00\x003\x00\x002\x00\x00/\x00\x00\x1b\x00\x00\x1a\x00\x00\x19\x00\x00\x18\x00\x00\x17\x00\x00\x16\x00\x00\x15\x00\x00\x14\x00\x00\x13\x00\x00\x12\x00\x00\x11\x00\x00\n\x00\x00\t\x00\x00\x08\x00\x00\x06\x00\x00\x05\x00\x00\x04\x00\x00\x03\x07\x00\xc0\x06\x00@\x04\x00\x80\x03\x00\x80\x02\x00\x80\x01\x00\x80\x00\x00\x02\x00\x00\x01\xe4i<+\xf6\xd6\x9b\xbb\xd3\x81\x9f\xbf\x15\xc1@\xa5o\x14,M \xc4\xc7\xe0\xb6\xb0\xb2\x1f\xf9)\xe8\x98',
                        '\x16\x03\0\0S\x01\0\0O\x03\0?G\xd7\xf7\xba,\xee\xea\xb2`~\xf3\0\xfd\x82{\xb9\xd5\x96\xc8w\x9b\xe6\xc4\xdb<=\xdbo\xef\x10n\0\0(\0\x16\0\x13\0\x0a\0f\0\x05\0\x04\0e\0d\0c\0b\0a\0`\0\x15\0\x12\0\x09\0\x14\0\x11\0\x08\0\x06\0\x03\x01\0',
                        '< NTP/1.2 >\n',
                        '< NTP/1.1 >\n',
                        '< NTP/1.0 >\n',
                        '\0Z\0\0\x01\0\0\0\x016\x01,\0\0\x08\0\x7F\xFF\x7F\x08\0\0\0\x01\0 \0:\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\04\xE6\0\0\0\x01\0\0\0\0\0\0\0\0(CONNECT_DATA=(COMMAND=version))',
                        '\x12\x01\x00\x34\x00\x00\x00\x00\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01\x02\x00\x1c\x00\x0c\x03\x00\x28\x00\x04\xff\x08\x00\x01\x55\x00\x00\x00\x4d\x53\x53\x51\x4c\x53\x65\x72\x76\x65\x72\x00\x48\x0f\x00\x00',
                        '\0\0\0\0\x44\x42\x32\x44\x41\x53\x20\x20\x20\x20\x20\x20\x01\x04\0\0\0\x10\x39\x7a\0\x01\0\0\0\0\0\0\0\0\0\0\x01\x0c\0\0\0\0\0\0\x0c\0\0\0\x0c\0\0\0\x04',
                        '\x01\xc2\0\0\0\x04\0\0\xb6\x01\0\0\x53\x51\x4c\x44\x42\x32\x52\x41\0\x01\0\0\x04\x01\x01\0\x05\0\x1d\0\x88\0\0\0\x01\0\0\x80\0\0\0\x01\x09\0\0\0\x01\0\0\x40\0\0\0\x01\x09\0\0\0\x01\0\0\x40\0\0\0\x01\x08\0\0\0\x04\0\0\x40\0\0\0\x01\x04\0\0\0\x01\0\0\x40\0\0\0\x40\x04\0\0\0\x04\0\0\x40\0\0\0\x01\x04\0\0\0\x04\0\0\x40\0\0\0\x01\x04\0\0\0\x04\0\0\x40\0\0\0\x01\x04\0\0\0\x02\0\0\x40\0\0\0\x01\x04\0\0\0\x04\0\0\x40\0\0\0\x01\0\0\0\0\x01\0\0\x40\0\0\0\0\x04\0\0\0\x04\0\0\x80\0\0\0\x01\x04\0\0\0\x04\0\0\x80\0\0\0\x01\x04\0\0\0\x03\0\0\x80\0\0\0\x01\x04\0\0\0\x04\0\0\x80\0\0\0\x01\x08\0\0\0\x01\0\0\x40\0\0\0\x01\x04\0\0\0\x04\0\0\x40\0\0\0\x01\x10\0\0\0\x01\0\0\x80\0\0\0\x01\x10\0\0\0\x01\0\0\x80\0\0\0\x01\x04\0\0\0\x04\0\0\x40\0\0\0\x01\x09\0\0\0\x01\0\0\x40\0\0\0\x01\x09\0\0\0\x01\0\0\x80\0\0\0\x01\x04\0\0\0\x03\0\0\x80\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\x01\x04\0\0\x01\0\0\x80\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\x40\0\0\0\x01\0\0\0\0\x01\0\0\x40\0\0\0\0\x20\x20\x20\x20\x20\x20\x20\x20\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\xff\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xe4\x04\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x7f',
                        '\x41\0\0\0\x3a\x30\0\0\xff\xff\xff\xff\xd4\x07\0\0\0\0\0\0test.$cmd\0\0\0\0\0\xff\xff\xff\xff\x1b\0\0\0\x01serverStatus\0\0\0\0\0\0\0\xf0\x3f\0',
                        'JDWP-Handshake',
                        'JRMI\x00\x02\x4b'
                    $Info=""
                    $socket = new-object System.Net.Sockets.TcpClient($thost, $port) 
                    $stream = $socket.GetStream()
                    $writer = new-object System.IO.StreamWriter $stream 
                    $SCRIPT:output = GetOutput 
                    $socket.Close()
                    $stream.Close() 
                    if ($output) {
                        #write-host "1 get data ",$thost,$port,$output
                        
                        $server = DisService $thost  $port  $output
                        if($server[2]){
                            $Info=$server[2]
                        }
                        $socket.Close()
                        $stream.Close() 
                        
                    }else{
                        
                        # write-host $thost,$port,"requests data"
                        foreach ($put in $putData) { 
                            # write-host $put 
                            $socket = new-object System.Net.Sockets.TcpClient($thost ,$port) 
                            $stream = $socket.GetStream()
                            $writer = new-object System.IO.StreamWriter $stream 
                            # $output=""
                            foreach ($line in $put) { 
                                $writer.WriteLine($line) 
                                $writer.Flush() 
                                $SCRIPT:output = GetOutput 
                            } 
                            if ($output) {
                                $service = DisService $thost  $port $output
                                if ($service[2] -eq 'http' ) {
                                    $WebTarget="http://"+$thost+":"+$port
                                    $Info=HashConvertTo-String(GetWebinfo $WebTarget)
                                    break
                                }
                                elseif ($service[2]) {
                                    $Info=$service[2]
                                    break
                                }
                            }
                            $socket.Close()
                            $writer.Close() 
                            $stream.Close() 
                        }
                    }
                    @{port=$port ; detail=$Info}

                }
                # get web info  title Status
                function GetWebInfo(){
                    Param (
                        $WebTarget
                    )

                    # write-host "this is get webinfo ",$WebTarget
                    $URI = New-Object Uri($WebTarget)
                    $Title="None"
                    try {
                        $WebRequest = [System.Net.WebRequest]::Create($URI)
                        $WebResponse = $WebRequest.GetResponse()
                        $WebStatus = $WebResponse.StatusCode
                        $ResultObject += $ScanObject
                        $ResStream = $WebResponse.GetResponseStream();
                        $Result = new-object System.IO.StreamReader $resStream
                        $Html = $result.ReadToEnd()
                        if ($Html -match "<title>(.*?)</title>"){$Title = $matches[1]}
                        $WebResponse.Close()
                    } catch {
                        $WebStatus = $Error[0].Exception.InnerException.Response.StatusCode
                        
                        if ($WebStatus -eq $null) {
                            # Not every exception returns a StatusCode.
                            # If that is the case, return the Status.
                            $WebStatus = $Error[0].Exception.InnerException.Status
                        }
                    } 
                    # write-host $WebStatus,$Title
                    @{ status = $WebStatus;title = $Title}
                    
                }
                Function HashConvertTo-String($ht) {
                    foreach($pair in $ht.GetEnumerator()) {
                    $output+=$pair.key + ":" + $pair.Value + ";"
                    }
                     $output
                }
                #  my pro main code 
                function Test-Port {

                    Param (
                        [Parameter(Mandatory = $True)] [String] $h,
                        [Parameter(Mandatory = $True)] [int] $p,
                        [Parameter(Mandatory = $True)] [int] $timeout
                    )

                    try {
                        $pAddress = [System.Net.IPAddress]::Parse($h)
                        $sockets[$p] = new-object System.Net.Sockets.TcpClient $pAddress.AddressFamily
                        
                    }
                    catch {
                        #we're assuming this is a host name
                        $sockets[$p] = new-object System.Net.Sockets.TcpClient
                    }

                    
                    $scriptBlockAsString = @"

                        #somewhat of a race condition with the timeout, but I don't think it matters

                       
                        if ( `$sockets[$p] -ne `$NULL)
                        {
                            if (!`$timeouts[$p].Disposed) {
                                `$timeouts[$p].Dispose()
                            }

                            `$status = `$sockets[$p].Connected;
                            if (`$status -eq `$True)
                            {
                                # write-host "$p is open"
                                `$openPorts.Add($p) 
                            }
                            else
                            {
                                # write-host "$p is closed"
                                `$closedPorts.Add($p)

                            }
                            `$sockets[$p].Close();
                            `$sockets.Remove($p)
                        }
"@
                    $timeoutCallback = @"
                        #write-host "$p is filtered"
                        `$sockets[$p].Close()
                        if (!`$timeouts[$p].Disposed) {
                            `$timeouts[$p].Dispose()
                            `$filteredPorts.Add($p)
                        }
                        `$sockets.Remove($p)
                        
"@

                    $timeoutCallback = [scriptblock]::Create($timeoutCallback)

                    $timeouts[$p] = New-Object System.Timers.Timer
                    Register-ObjectEvent -InputObject $timeouts[$p] -EventName Elapsed -Action $timeoutCallback | Out-Null
                    $timeouts[$p].Interval = $timeout
                    $timeouts[$p].Enabled = $true
                    $myscriptblock = [scriptblock]::Create($scriptBlockAsString)
                    $x = $sockets[$p].beginConnect($h, $p,(New-ScriptBlockCallback($myscriptblock)) , $null)

                }

                function PortScan-Alive
                {
                    Param (
                        [Parameter(Mandatory = $True)] [String] $h
                    )

                    Try
                    {

                        #ping
                        if ($hostPortList.Contains(-1))
                        {
                            $ping = new-object System.Net.NetworkInformation.Ping
                            $pResult = $ping.send($h)
                            if ($pResult.Status -eq "Success")
                            {
                                return $True
                            }
                        }
                        foreach($Port in $hostPortList)
                        {
                            if ($Port -ne -1)
                            {
                                Test-Port -h $h -p $Port -timeout $Timeout
                            }
                        }

                        do {
                            
                            Start-Sleep -Milli 100
                            if (($openPorts.Count -gt 0) -or ($closedPorts.Count -gt 0)) {
                                return $True
                            }
                        }
                        While ($sockets.Count -gt 0)

                    }
                    Catch
                    {
                        Write-Error "Exception trying to host scan $h"
                        Write-Error $_.Exception.Message;
                    }
                    write-host $openPorts.Count
                    return $False
                }

                function Portscan-Port
                {
                    Param (
                        [Parameter(Mandatory = $True)] [String] $h
                    )

                    [string[]]$Ports = @()

                    foreach($Port in $Portlist)
                    {
                        Try
                        {
                            Test-Port -h $h -p $Port -timeout $Timeout
                        }
                        Catch
                        {
                            Write-Error "Exception trying to scan $h port $Port"
                            Write-Error $_.Exception.Message;
                        }
                    }
                }
                [bool] $hostResult = $False
                write-host  $closedPorts
                if(!$SkipDiscovery)
                {
                    [bool] $hostResult = PortScan-Alive $thost
                    $openPorts.clear()
                    $closedPorts.clear()
                    $filteredPorts.Clear()
                }
                if((!$PingOnly) -and ($hostResult -or $SkipDiscovery))
                {
                    Portscan-Port $thost
                }
                while ($sockets.Count -gt 0) {
                    Start-Sleep -Milli 500
                }

                # my pro main code 
                $portInfo=@{}  # return port  info
                [string[]] $portService=@() # get service port 
     
                if($SPortsList -eq "*"){
                    $portService=$openPorts

                }elseif($SPortsList.contains(",")){
                    foreach($port in $openPorts){
                        if($SPortsList.split(',') -ccontains $port){
                            $portService += $port
                        }
                    }
                }else{
                    if($openPorts -ccontains $SPortsList){
                        $portService += $SPortsList
                    }
                }
              
                # remove some port 
                $remport=@(445,139,135,3389)
                
               
                foreach($port in $portService){
                    
                    if(!($remport -contains $port)){
                        #write-host $port
                        $info=GetService $thost $port      
                        $portInfo[$port]=$info['detail']
                    }
                  
                }
               
                # my pro main code end
                return @($hostResult, $openPorts, $closedPorts, $filteredPorts,$portInfo)
                }
            }
            
            # the outer loop is to flush the loop.
            # Otherwise Get-Job | Wait-Job could clog, etc
         
            [int]$saveIteration = 0
            [int]$computersDone=0
            [int]$upHosts=0
            while (($saveIteration * $SyncFreq) -lt $hostList.Count)
            {

                Get-Job | Remove-Job -Force
                $sIndex = ($saveIteration*$SyncFreq)
                $eIndex = (($saveIteration+1)*$SyncFreq)-1

                foreach ($iHost in $hostList[$sIndex..$eIndex])
                {
                    $ctr = @(Get-Job -state Running)
                    while ($ctr.Count -ge $nHosts)
                    {
                        Start-Sleep -Milliseconds $SleepTimer
                        $ctr = @(Get-Job -state Running)
                    }

                    $computersDone++
                    if(!$noProgressMeter)
                    {
                        Write-Progress -status "Port Scanning" -Activity $startMsg -CurrentOperation "starting computer $computersDone"  -PercentComplete ($computersDone / $hostList.Count * 100)
                    }

                    Start-Job -ScriptBlock $portScanCode -Name $iHost -ArgumentList @($iHost, $SkipDiscovery, $PingOnly, $Timeout, $portList, $hostPortList, $Threads,$Sports)  | Out-Null
                }

                Get-Job | Wait-Job | Out-Null

                foreach ($job in Get-Job)
                {
                    $jobOut = @(Receive-Job $job)
                    [bool]$hostUp = $jobOut[0]
                    $jobName = $job.Name
                    $portServices = $jobOut[4]
                    $openPorts = $jobOut[1]
                    $closedPorts = $jobOut[2]
                    $filteredPorts = $jobOut[3]

                    if($hostUp) {
                        $upHosts ++
                    }

                    if (!$quiet)
                    {
                        $hostDate = Get-Date
                        $hostObj = New-Object System.Object
                        $hostObj | Add-Member -MemberType Noteproperty -Name Hostname -Value $jobName
                        $hostObj | Add-Member -MemberType Noteproperty -Name alive -Value $hostUp
                        $hostObj | Add-Member -MemberType Noteproperty -Name openPorts -Value $openPorts
                        $hostObj | Add-Member -MemberType Noteproperty -Name closedPorts -Value $closedPorts
                        $hostObj | Add-Member -MemberType Noteproperty -Name filteredPorts -Value $filteredPorts
                        $hostObj | Add-Member -MemberType NoteProperty -Name finishTime -Value $hostDate
                        # my pro main code 
                        $hostObj | Add-Member -MemberType NoteProperty -Name port -Value "service"
                        
                        foreach($pair in  $portServices.GetEnumerator()){

                            $hostObj | Add-Member -MemberType Noteproperty -Name $pair.key -Value $pair.value
                        }
                        # my pro main code end
                        $scannedHostList += $hostobj
                    }

                    Write-PortscanOut -outhost $jobName -isUp $hostUp -openPorts $openPorts -closedPorts $closedPorts -filteredPorts $filteredPorts -grepStream $grepStream -xmlStream $xmlStream -readableStream $readableStream -SkipDiscovery $SkipDiscovery
                }

                if ($grepStream) {
                    $grepStream.flush()
                }
                if ($xmlStream) {
                    $xmlStream.flush()
                }
                if($readableStream) {
                    $readableStream.flush()
                }

                $saveIteration ++
            }

            $enddate = Get-Date
            $totaltime = ($enddate - $startdate).TotalSeconds
            $endMsg = "Port scan complete at $enddate ($totaltime seconds)"
            if (!$SkipDiscovery) {
                $endMsg += ", $upHosts hosts are up"
            }

            Write-PortscanOut -comment $endMsg -grepStream $grepStream -xmlStream $xmlStream -readableStream $readableStream

            if($grepStream) {
                $grepStream.Close()
            }
            if ($xmlStream) {
                $xmlStream.Close()
            }
            if($readableStream) {
                $readableStream.Close()
            }

            return $scannedHostList

        }
        Catch
        {
            Write-Error $_.Exception.Message;
        }
    }
}
