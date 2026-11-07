#include "libBimeronCore.h"
#include <assert.h>
#include <pthread.h>
#include <string.h>
#include <unistd.h>

static void *reader(void *arg) {
    unsigned char output[65535];
    unsigned long long handle = *(unsigned long long *)arg;
    assert(RLReadPacket(handle, output, sizeof(output), 1000) == -1);
    return NULL;
}
int main(void) {
    char config[] = "[Profile]\nVersion = 1\n[AccessKey]\nSS = ss://YWVzLTI1Ni1nY206c2VjcmV0@127.0.0.1:8388\n";
    char file_config[] = "[Profile]\nVersion = 1\n[AccessKey]\nFile = secret.key\n";
    char kill_switch_config[] = "[Profile]\nVersion = 1\n[AccessKey]\nSS = ss://YWVzLTI1Ni1nY206c2VjcmV0@127.0.0.1:8388\n[Interface]\nKillSwitch = true\n";
    assert(RLCreate(NULL,0) == 0);
    assert(RLCreate(file_config, (int)strlen(file_config)) == 0);
    assert(RLCreate(kill_switch_config, (int)strlen(kill_switch_config)) == 0);
    assert(RLCreateWithGeoData(NULL, 0, NULL, 0, NULL, 0) == 0);
    assert(RLCreateWithGeoData(config, (int)strlen(config), config, 67108865, NULL, 0) == 0);
    assert(RLCreateWithGeoData(kill_switch_config, (int)strlen(kill_switch_config), NULL, 0, NULL, 0) == 0);
    unsigned long long geo_handle = RLCreateWithGeoData(config, (int)strlen(config), NULL, 0, NULL, 0);
    assert(geo_handle != 0);
    assert(RLStop(geo_handle) == 0);
    char *caps = RLCapabilities();
    assert(caps && strstr(caps, "\"geoip_split\":true") && strstr(caps, "\"geosite_split\":true") && strstr(caps, "geodata_schema")); RLFree(caps);
    char ip_kind[] = "geoip";
    unsigned char dataset[] = {10, 6, 10, 4, 'T', 'E', 'S', 'T'};
    char *good_groups = RLGeoDataGroups(ip_kind, dataset, sizeof(dataset));
    assert(good_groups && strcmp(good_groups, "{\"groups\":[\"test\"],\"error\":null}") == 0); RLFree(good_groups);
    unsigned char malformed[] = {255};
    char *bad_groups = RLGeoDataGroups(ip_kind, malformed, sizeof(malformed));
    assert(bad_groups && strstr(bad_groups, "\"details\":{") && strstr(bad_groups, "geodata_invalid")); RLFree(bad_groups);
    char geo_config[] = "[Profile]\nVersion = 1\n[AccessKey]\nSS = ss://YWVzLTI1Ni1nY206c2VjcmV0@127.0.0.1:8388\n[Rule]\nGeoIP = test\nAction = direct\n";
    unsigned long long dataset_handle = RLCreateWithGeoData(geo_config, (int)strlen(geo_config), dataset, sizeof(dataset), NULL, 0);
    assert(dataset_handle != 0);
    memset(dataset, 0, sizeof(dataset));
    assert(RLStop(dataset_handle) == 0);
    char kind[] = "invalid";
    char *groups = RLGeoDataGroups(kind, NULL, 0);
    assert(groups && strstr(groups, "\"error\":\"")); RLFree(groups);
    groups = RLGeoDataGroups(NULL, config, -1);
    assert(groups && strstr(groups, "\"error\":\"")); RLFree(groups);
    groups = RLGeoDataGroups(kind, config, 67108865);
    assert(groups && strstr(groups, "maximum 64 MiB")); RLFree(groups);
    assert(RLCreateWithGeoData(config, (int)strlen(config), NULL, 1, NULL, 0) == 0);
    assert(RLCreateWithGeoData(config, (int)strlen(config), NULL, 0, config, -1) == 0);
    assert(RLCreateWithGeoData(config, (int)strlen(config), NULL, 0, config, 67108865) == 0);
    char *validation = RLValidateConfigWithGeoData(config, (int)strlen(config), NULL, 0, NULL, 0);
    assert(validation && strstr(validation, "\"error\":null")); RLFree(validation);
    validation = RLValidateConfigWithGeoData(kill_switch_config, (int)strlen(kill_switch_config), NULL, 0, NULL, 0);
    assert(validation && strstr(validation, "\"error\":\"") && strstr(validation, "\"code\":\"embedded_kill_switch_unsupported\"")); RLFree(validation);
    char *catalog = RLErrorCatalog();
    assert(catalog && strstr(catalog, "\"embedded_requires_vpn_mode\"") && strstr(catalog, "\"ru\":")); RLFree(catalog);
    char ikev2_config[] = "[Profile]\nVersion = 1\n[IKEv2]\nWindowsProfile = Corporate VPN\nServerName = vpn.example.com\n[Interface]\nMode = vpn\n";
    assert(RLCreate(ikev2_config, (int)strlen(ikev2_config)) == 0);
    assert(RLCreateWithGeoData(ikev2_config, (int)strlen(ikev2_config), NULL, 0, NULL, 0) == 0);
    validation = RLValidateConfigWithGeoData(ikev2_config, (int)strlen(ikev2_config), NULL, 0, NULL, 0);
    assert(validation && strstr(validation, "\"error\":\"")); RLFree(validation);
    unsigned long long handle = RLCreate(config, (int)strlen(config));
    assert(handle != 0);
    char *version = RLVersion();
    assert(version && strstr(version,"\"version\":")); RLFree(version);
    char *settings = RLSettings(handle);
    assert(settings && strstr(settings,"\"mtu\":1420")); RLFree(settings);
    char *status = RLStatus(handle);
    assert(status && strstr(status,"disconnected")); RLFree(status);
    char *events = RLEvents(handle);
    assert(events && strcmp(events,"[]") == 0); RLFree(events);
    unsigned char output[65535];
    assert(RLReadPacket(handle,output,sizeof(output)-1,1) == -1);
    assert(RLReadPacket(handle,output,sizeof(output),0) == -1);
    assert(RLReadPacket(handle,output,sizeof(output),1) == 0);
    assert(RLWritePacket(handle,config,4) == -1);
    RLNetworkChanged(handle);
    pthread_t thread;
    assert(pthread_create(&thread,NULL,reader,&handle) == 0);
    usleep(20000);
    assert(RLStop(handle) == 0);
    assert(pthread_join(thread,NULL) == 0);
    assert(RLStatus(handle) == NULL);
    assert(RLStop(handle) == 0);
    return 0;
}
