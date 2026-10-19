#!/bin/sh
# Technical host + packet extension, no GUI. Run on macOS.
set -eu
cd "$(dirname "$0")/.."
test "$(uname -s)" = Darwin
export MACOSX_DEPLOYMENT_TARGET=13.0
export BUNDLE_ID="${BUNDLE_ID:-org.bimeron.core.dev}"
export TEAM_ID="${TEAM_ID:-}"
export APPLE_EXTENSION_KIND="${APPLE_EXTENSION_KIND:-system-extension}"
case "$APPLE_EXTENSION_KIND" in app-extension|system-extension) ;; *) exit 1 ;; esac
case "$(uname -m)" in arm64) APPLE_ARCH=arm64 ;; x86_64) APPLE_ARCH=amd64 ;; *) echo 'Unsupported Mac architecture' >&2; exit 1 ;; esac
export APPLE_BUILD_DIR="${APPLE_BUILD_DIR:-$PWD/dist/apple-$APPLE_EXTENSION_KIND-$APPLE_ARCH}"
mkdir -p "$APPLE_BUILD_DIR/bridge"
go build -buildmode=c-archive -o "$APPLE_BUILD_DIR/bridge/libBimeronCore.a" ./cmd/bimeron-apple
cat > "$APPLE_BUILD_DIR/bridge/module.modulemap" <<'EOF'
module CoreBridge {
    header "libBimeronCore.h"
    export *
}
EOF
python3 - <<'PY'
import os, pathlib, plistlib
root=pathlib.Path(os.environ['APPLE_BUILD_DIR'])
bundle=os.environ['BUNDLE_ID']; team=os.environ['TEAM_ID']
system=os.environ['APPLE_EXTENSION_KIND']=='system-extension'
app=root/'BimeronCore.app'/'Contents'
extension=(app/'Library'/'SystemExtensions'/(bundle+'.packet.systemextension') if system else app/'PlugIns'/'BimeronPacketTunnel.appex')/'Contents'
for directory in (app,extension): (directory/'MacOS').mkdir(parents=True,exist_ok=True)
group=team+'.'+bundle if team else ''
common={'CFBundleVersion':'1','CFBundleShortVersionString':'0.1.0','LSMinimumSystemVersion':'13.0','RLKeychainGroup':group,'RLExtensionKind':os.environ['APPLE_EXTENSION_KIND']}
host=dict(common,CFBundleIdentifier=bundle,CFBundleExecutable='BimeronControl',CFBundleName='Bimeron Core',CFBundlePackageType='APPL',LSUIElement=True)
provider=dict(common,CFBundleIdentifier=bundle+'.packet',CFBundleExecutable='BimeronPacketTunnel',CFBundleName='Bimeron Packet Tunnel',CFBundlePackageType='XPC!',NSExtension={'NSExtensionPointIdentifier':'com.apple.networkextension.packet-tunnel','NSExtensionPrincipalClass':'BimeronPacketTunnel.PacketTunnelProvider'})
if system:
    host['NSSystemExtensionUsageDescription']='Bimeron Core provides the system VPN tunnel.'
    provider.pop('NSExtension')
    provider['CFBundlePackageType']='SYSX'
    provider['NetworkExtension']={'NEProviderClasses':{'com.apple.networkextension.packet-tunnel':'BimeronPacketTunnel.PacketTunnelProvider'},'NEMachServiceName':(team or 'UNSIGNED')+'.'+bundle+'.packet'}
for path,value in ((app/'Info.plist',host),(extension/'Info.plist',provider)):
    with path.open('wb') as f: plistlib.dump(value,f)
ent={'com.apple.developer.networking.networkextension':['packet-tunnel-provider-systemextension' if system else 'packet-tunnel-provider']}
if team:
    ent['com.apple.developer.team-identifier']=team
    ent['keychain-access-groups']=[group]
for name,sandbox in (('host',False),('provider',True)):
    value=dict(ent)
    if team: value['com.apple.application-identifier']=team+'.'+bundle+('.packet' if sandbox else '')
    if system and not sandbox: value['com.apple.developer.system-extension.install']=True
    if system and sandbox: value.pop('keychain-access-groups',None)
    if sandbox: value.update({'com.apple.security.app-sandbox':True,'com.apple.security.network.client':True,'com.apple.security.network.server':True})
    with (root/(name+'.entitlements')).open('wb') as f: plistlib.dump(value,f)
PY
APP="$APPLE_BUILD_DIR/BimeronCore.app/Contents"
if test "$APPLE_EXTENSION_KIND" = system-extension; then
    EXT_BUNDLE="$APP/Library/SystemExtensions/$BUNDLE_ID.packet.systemextension"
else
    EXT_BUNDLE="$APP/PlugIns/BimeronPacketTunnel.appex"
fi
EXT="$EXT_BUNDLE/Contents"
SDK=$(xcrun --sdk macosx --show-sdk-path)
if test "$APPLE_EXTENSION_KIND" = system-extension; then
    swiftc -sdk "$SDK" -swift-version 5 -I "$APPLE_BUILD_DIR/bridge" -module-name BimeronPacketTunnel -parse-as-library apple/Shared/ProfileStore.swift apple/PacketTunnel/PacketTunnelProvider.swift apple/PacketTunnel/system-main.swift "$APPLE_BUILD_DIR/bridge/libBimeronCore.a" -framework NetworkExtension -framework Network -framework Security -framework Foundation -o "$EXT/MacOS/BimeronPacketTunnel"
else
    swiftc -sdk "$SDK" -swift-version 5 -I "$APPLE_BUILD_DIR/bridge" -module-name BimeronPacketTunnel -application-extension -parse-as-library apple/Shared/ProfileStore.swift apple/PacketTunnel/PacketTunnelProvider.swift "$APPLE_BUILD_DIR/bridge/libBimeronCore.a" -framework NetworkExtension -framework Network -framework Security -framework Foundation -Xlinker -e -Xlinker _NSExtensionMain -o "$EXT/MacOS/BimeronPacketTunnel"
fi
swiftc -sdk "$SDK" -swift-version 5 -I "$APPLE_BUILD_DIR/bridge" apple/Shared/ProfileStore.swift apple/Control/SystemActivation.swift apple/Control/main.swift "$APPLE_BUILD_DIR/bridge/libBimeronCore.a" -framework NetworkExtension -framework SystemExtensions -framework Security -framework Foundation -o "$APP/MacOS/BimeronControl"
clang -I "$APPLE_BUILD_DIR/bridge" apple/Tests/bridge.c "$APPLE_BUILD_DIR/bridge/libBimeronCore.a" -lpthread -framework CoreFoundation -framework Security -framework Foundation -o "$APPLE_BUILD_DIR/bridge-test"
"$APPLE_BUILD_DIR/bridge-test"
if test -n "${SIGN_IDENTITY:-}"; then
    test -n "$TEAM_ID"
    test -f "${HOST_PROFILE:-}" && test -f "${EXTENSION_PROFILE:-}"
    export HOST_PROFILE EXTENSION_PROFILE
    python3 - <<'PY'
import os,plistlib,subprocess,fnmatch,datetime
team=os.environ['TEAM_ID']; bundle=os.environ['BUNDLE_ID']; system=os.environ['APPLE_EXTENSION_KIND']=='system-extension'
for name,extension in (('HOST_PROFILE',False),('EXTENSION_PROFILE',True)):
    data=subprocess.check_output(['/usr/bin/security','cms','-D','-i',os.environ[name]])
    profile=plistlib.loads(data); ent=profile.get('Entitlements',{})
    appid=team+'.'+bundle+('.packet' if extension else '')
    expected='packet-tunnel-provider-systemextension' if system else 'packet-tunnel-provider'
    actual=ent.get('com.apple.application-identifier',ent.get('application-identifier',''))
    if team not in profile.get('TeamIdentifier',[]) or actual != appid or expected not in ent.get('com.apple.developer.networking.networkextension',[]):
        raise SystemExit('Profile does not authorize this Team, bundle ID and NetworkExtension type: '+name)
    expiry=profile.get('ExpirationDate')
    if not expiry or expiry.replace(tzinfo=datetime.timezone.utc)<=datetime.datetime.now(datetime.timezone.utc):
        raise SystemExit('Expired provisioning profile: '+name)
    if not extension and system and not ent.get('com.apple.developer.system-extension.install'):
        raise SystemExit('Host profile lacks system-extension.install')
    if not (extension and system):
        if not any(fnmatch.fnmatchcase(team+'.'+bundle,group) for group in ent.get('keychain-access-groups',[])):
            raise SystemExit('Profile lacks required Keychain access group: '+name)
PY
    cp "$HOST_PROFILE" "$APP/embedded.provisionprofile"
    cp "$EXTENSION_PROFILE" "$EXT/embedded.provisionprofile"
    codesign --force --sign "$SIGN_IDENTITY" --entitlements "$APPLE_BUILD_DIR/provider.entitlements" "$EXT_BUNDLE"
    codesign --force --sign "$SIGN_IDENTITY" --entitlements "$APPLE_BUILD_DIR/host.entitlements" "$APPLE_BUILD_DIR/BimeronCore.app"
    codesign --verify --deep --strict "$APPLE_BUILD_DIR/BimeronCore.app"
    rm -f "$APPLE_BUILD_DIR/UNSIGNED.txt"
else
    printf '%s\n' 'Unsigned build only: NetworkExtension execution requires valid signing and provisioning.'
    printf '%s\n' 'Unsigned build only: NetworkExtension execution requires valid signing and provisioning.' > "$APPLE_BUILD_DIR/UNSIGNED.txt"
fi
cp LICENSE THIRD_PARTY_NOTICES.txt "$APPLE_BUILD_DIR/"
printf '%s\n' "$APPLE_BUILD_DIR/BimeronCore.app"
