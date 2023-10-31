#ifndef CREDENTIALMANAGER_H
#define CREDENTIALMANAGER_H

#include <stdint.h>
#include <stdlib.h>

__attribute__((import_module("credman"), import_name("AddEntry")))
void AddEntry(long long cred_id, char* icon, size_t icon_len, char *title, char *subtitle, char *disclaimer, char *warning);

__attribute__((import_module("credman"), import_name("AddField")))
void AddField(long long cred_id, char *field_display_name, char *field_display_value);

__attribute__((import_module("credman"), import_name("GetRequestBuffer")))
void GetRequestBuffer(void* buffer);

__attribute__((import_module("credman"), import_name("GetRequestSize")))
void GetRequestSize(uint32_t* size);

__attribute__((import_module("credman"), import_name("ReadCredentialsBuffer")))
size_t ReadCredentialsBuffer(void* buffer, size_t offset, size_t len);

__attribute__((import_module("credman"), import_name("GetCredentialsSize")))
void GetCredentialsSize(uint32_t* size);

typedef struct CallingAppInfo {
	char package_name[256];
	char origin[512];
} CallingAppInfo;

__attribute__((import_module("credman"), import_name("GetCallingAppInfo")))
void GetCallingAppInfo(CallingAppInfo* info);

void* GetRequest() {
	uint32_t size;
	GetRequestSize(&size);
	void* buffer = malloc(size);
	GetRequestBuffer(buffer);
	return buffer;
}

void* GetCredentials() {
	uint32_t size;
	GetCredentialsSize(&size);
	void* buffer = malloc(size);
	ReadCredentialsBuffer(buffer, 0, size);
	return buffer;
}

#endif 
