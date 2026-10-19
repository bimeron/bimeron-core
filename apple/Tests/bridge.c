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
