param([Parameter(Mandatory=$true)][ValidatePattern('^[a-f0-9]{64}$')][string]$Nonce,
 [ValidateRange(5,1800)][int]$Seconds=600,[string]$Root='C:/BimeronStep10Probe')
$ErrorActionPreference='Stop'
. "$PSScriptRoot/cancellation.ps1"
$script:stopRequest=$null
function Check-Stop {$script:stopRequest=Read-ProbeStop "$PSScriptRoot/stop-request.json" $Nonce;if($script:stopRequest){throw 'Cooperative cancellation'}}
Add-Type -Path "$PSScriptRoot/Journal.cs"
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
$principal=[Security.Principal.WindowsPrincipal]::new($identity)
if($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Ordinary token required'}
$process=Get-Process -Id $PID
$producer=@{pid=$PID;start=$process.StartTime.ToUniversalTime().ToString('o');sid=$identity.User.Value}
$journal=$null;$udp=@();$tcp=@();$exact=@();$script:phase='PRE';$script:challenge=$null;$terminal=$null;$script:sequence=0;$script:round=0
function Record($kind,$target,$status,$detail=$null){
 $script:sequence++
 $row=@{nonce=$Nonce;sequence=$script:sequence;round=$script:round;producer=$producer;utc=[DateTime]::UtcNow.ToString('o');ticks=[Diagnostics.Stopwatch]::GetTimestamp();kind=$kind;target=$target;status=$status}
 if($null -ne $detail){$row.detail=$detail}
 if($kind -ceq 'end' -and $status -ceq 'cancelled'){$row.requestId=$script:stopRequest.requestId}
 $journal.Record(($row|ConvertTo-Json -Depth 12 -Compress))
}
function Socket-State($u){
 $s=$u.socket
 if($s.Handle.ToInt64() -le 0 -or $s.Handle.ToInt64().ToString() -cne $u.handle){throw 'Retained socket handle lost'}
 $v=@{id=$u.id;handle=$u.handle;local=$s.LocalEndPoint.ToString();remote=$s.RemoteEndPoint.ToString();family=$s.AddressFamily.ToString();type=$s.SocketType.ToString();protocol=$s.ProtocolType.ToString();exclusive=$s.ExclusiveAddressUse;session=$process.SessionId}
 if($v.local -cne "192.0.2.2:$($u.port)" -or $v.remote -cne "<LAB_PUBLIC_IP>:$($u.port)"){throw 'Retained socket tuple changed'}
 return $v
}
function Challenge-Boundary {
 if(!$script:challenge -and (Test-Path -LiteralPath "$PSScriptRoot/transition.json")){$script:phase='TRANSITION'}
 $path="$PSScriptRoot/post-arm.json"
 if(!(Test-Path -LiteralPath $path)){return}
 $raw=[IO.File]::ReadAllBytes($path)
 $h=[Security.Cryptography.SHA256]::Create();try{$hash=([BitConverter]::ToString($h.ComputeHash($raw))).Replace('-','').ToLowerInvariant()}finally{$h.Dispose()}
 if($script:challenge){if($hash -cne $script:challenge.hash){throw 'Challenge replaced'};return}
 $c=[Text.Encoding]::UTF8.GetString($raw)|ConvertFrom-Json
 $names=@('schema','nonce','measurementNonce','requestId','producerPinSHA256','policySHA256','ackSHA256','owner','producer')
 if(@($c.PSObject.Properties.Name).Count -ne $names.Count -or @($c.PSObject.Properties.Name|Where-Object {$_ -cnotin $names}).Count -or $c.schema -cne 'c1pe-challenge-v1' -or $c.nonce -cne $Nonce -or $c.measurementNonce -cnotmatch '^[a-f0-9]{64}$' -or $c.measurementNonce -ceq $Nonce -or $c.requestId -cnotmatch '^[a-f0-9]{32}$'){throw 'Invalid challenge'}
 foreach($key in @('producerPinSHA256','policySHA256','ackSHA256')){if($c.$key -cnotmatch '^[a-f0-9]{64}$'){throw 'Invalid challenge binding'}}
 foreach($key in @('pid','start','sid')){if($c.producer.$key -cne $producer[$key]){throw 'Challenge producer mismatch'}}
 $script:challenge=@{hash=$hash;value=$c};$script:phase='POST'
 Record 'post-arm-fence' 'all' 'consumed' @{challengeSHA256=$hash;requestId=$c.requestId;measurementNonce=$c.measurementNonce;frequency=[Diagnostics.Stopwatch]::Frequency;sockets=@($exact|ForEach-Object {Socket-State $_})}
}
function Payload([int]$port,[bool]$isTcp){
 if($port -ne 53){return ,[Text.Encoding]::ASCII.GetBytes("STEP10-$Nonce-ROUND-$script:round-END")}
 $bytes=[Collections.Generic.List[byte]]::new()
 $bytes.AddRange([byte[]]@(0x53,0x10,1,0,0,1,0,0,0,0,0,0))
 foreach($label in @('s10',$Nonce.Substring(0,32),$Nonce.Substring(32),"r$script:round",'test')){
  $b=[Text.Encoding]::ASCII.GetBytes($label);$bytes.Add([byte]$b.Length);$bytes.AddRange($b)
 }
 $bytes.AddRange([byte[]]@(0,0,1,0,1));$data=$bytes.ToArray()
 if($isTcp){return ,([byte[]]@([byte]($data.Length -shr 8),[byte]($data.Length -band 255))+$data)}
 return ,$data
}
try{
 $journal=[ProbeJournal]::new((Join-Path $Root "probe-$Nonce.jsonl"))
 $timer=[Diagnostics.Stopwatch]::StartNew();$origin=[Diagnostics.Stopwatch]::GetTimestamp()
 Record 'start' 'all' ((@{origin=$origin;frequency=[Diagnostics.Stopwatch]::Frequency;seconds=$Seconds}|ConvertTo-Json -Compress));Check-Stop
 foreach($address in @('192.0.2.1','fd42:8::1','<LAB_PUBLIC_IP>')){
  $family=if($address.Contains(':')){[Net.Sockets.AddressFamily]::InterNetworkV6}else{[Net.Sockets.AddressFamily]::InterNetwork}
  Check-Stop;foreach($port in $(if($address -eq '<LAB_PUBLIC_IP>'){@(500,4500)}else{@(49000,53)})){
   Check-Stop
   $s=[Net.Sockets.Socket]::new($family,[Net.Sockets.SocketType]::Dgram,[Net.Sockets.ProtocolType]::Udp);$s.SendTimeout=500;$s.ExclusiveAddressUse=$true
   $sourceAddress=if($family -eq [Net.Sockets.AddressFamily]::InterNetworkV6){'fd42:8::2'}else{'192.0.2.2'}
   $s.Bind([Net.IPEndPoint]::new([Net.IPAddress]::Parse($sourceAddress),0))
   $udp+=@{socket=$s;address=$address;port=$port;target="udp/${address}/$port"}
  }
  if($address -ne '<LAB_PUBLIC_IP>'){
   Check-Stop;foreach($port in @(53,8080)){
    Check-Stop
    $s=[Net.Sockets.TcpClient]::new($family);$s.SendTimeout=500;$status='connected'
    try{if(!$s.ConnectAsync($address,$port).Wait(1000)){throw 'Connect timeout'}}catch{$status='unavailable'}
    $tcp+=@{socket=$s;address=$address;port=$port;target="tcp/${address}/$port";connected=($status -eq 'connected')}
    Record 'tcp-open' "tcp/${address}/$port" $status
   }
  }
 }
 foreach($port in @(500,4500)){
  Check-Stop
  $s=[Net.Sockets.Socket]::new([Net.Sockets.AddressFamily]::InterNetwork,[Net.Sockets.SocketType]::Dgram,[Net.Sockets.ProtocolType]::Udp)
  $u=@{socket=$s;port=$port;target="carrier/<LAB_PUBLIC_IP>/$port";id=($Nonce+'-'+$port);handle=$s.Handle.ToInt64().ToString()};$exact+=$u
  $s.ExclusiveAddressUse=$true;$s.SendTimeout=500
  $s.Bind([Net.IPEndPoint]::new([Net.IPAddress]::Parse('192.0.2.2'),$port))
  $s.Connect([Net.IPEndPoint]::new([Net.IPAddress]::Parse('<LAB_PUBLIC_IP>'),$port))
  $u.opened=$true;Record 'socket-open' $u.target 'connected' (Socket-State $u)
 }
 while($timer.Elapsed.TotalSeconds -lt $Seconds){
  Challenge-Boundary
  Check-Stop;$script:round++;Record 'round-start' 'all' 'begin'
  foreach($u in $udp){Check-Stop
   Record 'attempt' $u.target 'send';$status='sent'
   try{$data=Payload $u.port $false;$sent=$u.socket.SendTo($data,[Net.IPEndPoint]::new([Net.IPAddress]::Parse($u.address),$u.port));$status="sent:$sent local=$($u.socket.LocalEndPoint)"}catch{$status='send-error:'+ $_.Exception.GetType().Name}
   Record 'result' $u.target $status
  }
  foreach($t in $tcp){Check-Stop
   Record 'attempt' $t.target 'preexisting-send';$status='unavailable'
   if($t.connected){try{$data=Payload $t.port $true;$t.socket.GetStream().Write($data,0,$data.Length);$status="sent local=$($t.socket.Client.LocalEndPoint)"}catch{$status='send-error:'+ $_.Exception.GetType().Name}}
   Record 'result' $t.target $status
  }
  foreach($u in $exact){
   Check-Stop;$state=Socket-State $u
   $detail=@{socket=$state;phase=$script:phase;measurementNonce=$(if($script:challenge){$script:challenge.value.measurementNonce}else{'-'})}
   Record 'attempt' $u.target 'preexisting-connected-send' $detail
   $data=[Text.Encoding]::ASCII.GetBytes("C1PE|$Nonce|$script:phase|$($detail.measurementNonce)|$($u.id)|$($u.port)|$script:round")
   $count=0;$errorCode=0
   try{$count=$u.socket.Send($data);$status="sent:$count local=$($u.socket.LocalEndPoint)"}catch{
    $e=$_.Exception;while($e.InnerException){$e=$e.InnerException}
    if($e -isnot [Net.Sockets.SocketException]){throw};$errorCode=[int]$e.SocketErrorCode;$status="send-error:$errorCode"
   }
   $detail=@{socket=(Socket-State $u);phase=$script:phase;measurementNonce=$detail.measurementNonce;bytes=$count;socketError=$errorCode}
   Record 'result' $u.target $status $detail
  }
  Record 'round-complete' 'all' 'complete';1..2|ForEach-Object {Check-Stop;Start-Sleep -Milliseconds 250}
 }
 Check-Stop;$terminal='complete'
}catch{if($script:stopRequest -and $journal){$terminal='cancelled'}else{throw}}finally{
 if($journal){Record 'measurement-end' 'all' $(if($terminal){$terminal}else{'error'})}
 foreach($u in $exact){$state=$null;if($u.opened){$state=Socket-State $u};$u.socket.Dispose();if($state -and $journal){Record 'socket-close' $u.target 'disposed' $state}}
 foreach($u in $udp){$u.socket.Dispose()};foreach($t in $tcp){$t.socket.Dispose()};if($journal){if($terminal){Record 'end' 'all' $terminal};$journal.Dispose()}
}
