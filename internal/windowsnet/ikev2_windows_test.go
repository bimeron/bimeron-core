//go:build windows

package windowsnet

import "testing"

const nativeDNSTag = "BimeronIKEv2DNS:0123456789abcdef0123456789abcdef"
const nativeDNSMocks = `
$global:rules=@()
function Get-DnsClientNrptPolicy { param([switch]$Effective) }
function Add-DnsClientNrptRule {
 param($Namespace,$NameServers,$Comment)
 $global:rules += [pscustomobject]@{Name='native-owned';Comment=$Comment;Namespace=@($Namespace);NameServers=@($NameServers)}
}
`

func TestNativeDNSSetupCleanupAndForeignPolicyConflict(t *testing.T) {
	body := nativeDNSMocks + `
 $null=& {` + nativeDNSScript + `}
 $taskConfig.action='cleanup'
 $null=& {` + nativeDNSScript + `}
 @{removed=@($global:removedDns);names=@($global:rules | ForEach-Object {$_.Namespace})} | ConvertTo-Json -Compress`
	r := mocked(t, Config{Action: "setup", Tag: nativeDNSTag, DNS: []string{"10.77.55.1"}}, body)
	if len(r["removed"].([]any)) != 1 || r["removed"].([]any)[0] != "native-owned" {
		t.Fatal(r)
	}
	body = nativeDNSMocks + `
 $global:rules=@([pscustomobject]@{Name='foreign';Comment='Administrator'})
 $caught=$false
 try { $null=& {` + nativeDNSScript + `} } catch { $caught=$true }
 @{caught=$caught;removed=@($global:removedDns);count=$global:rules.Count} | ConvertTo-Json -Compress`
	r = mocked(t, Config{Action: "setup", Tag: nativeDNSTag, DNS: []string{"10.77.55.1"}}, body)
	if r["caught"] != true || len(r["removed"].([]any)) != 0 || r["count"] != float64(1) {
		t.Fatal(r)
	}
}

func TestNativeDNSCleanupRejectsModifiedRuleAndRecoveryIsOwned(t *testing.T) {
	body := nativeDNSMocks + `
 $global:rules=@([pscustomobject]@{Name='native-owned';Comment=$taskConfig.tag;Namespace=@('.');NameServers=@('192.0.2.1')})
 $caught=$false
 try { $null=& {` + nativeDNSScript + `} } catch { $caught=$true }
 $taskConfig.action='recover'
 $global:rules += [pscustomobject]@{Name='foreign';Comment='Administrator'}
 $null=& {` + nativeDNSScript + `}
 @{caught=$caught;removed=@($global:removedDns)} | ConvertTo-Json -Compress`
	r := mocked(t, Config{Action: "cleanup", Tag: nativeDNSTag, DNS: []string{"10.77.55.1"}}, body)
	if r["caught"] != true || len(r["removed"].([]any)) != 1 || r["removed"].([]any)[0] != "native-owned" {
		t.Fatal(r)
	}
}
