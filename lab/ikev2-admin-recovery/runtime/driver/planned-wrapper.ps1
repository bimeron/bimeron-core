param([int]$Seconds)
$ErrorActionPreference='Stop'
try { & 'C:/BimeronStep10Probe/1b43054c5949dd7c6c4474e3362868d7e50aa05871443e81176a4edb25bd15b5/probe.ps1' -Nonce '1b43054c5949dd7c6c4474e3362868d7e50aa05871443e81176a4edb25bd15b5' -Seconds 900 -Root 'C:/BimeronStep10Probe/1b43054c5949dd7c6c4474e3362868d7e50aa05871443e81176a4edb25bd15b5/logs'; exit 0 } catch { [Console]::Error.WriteLine($_.Exception.ToString()); exit 1 }
