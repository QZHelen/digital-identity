#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <unistd.h>
#include "cJSON.h"
#include "../credentialmanager.h"

#define Matcher_NONE (0)
#define Matcher_EQUAL (1 << 0)

typedef struct Matcher {
    char *name;
    int type;
    struct cJSON *matcher_value;
    struct Matcher *next;
} Matcher;

static void init_matcher(Matcher *curr, char *name, int type, cJSON *matcher_value, Matcher *next) {
    curr->name = name;
    curr->type = type;
    // TODO: store the value immediately for better efficiency.
    curr->matcher_value = matcher_value;
    curr->next = next;
}

// TODO: add full validation and refactoring for repeating logic.
int main() {
	printf("Identity Credentials Matcher\n");
	void* request = GetRequest();
	void* credentials = GetCredentials();

    CallingAppInfo *appInfo = malloc(sizeof(CallingAppInfo));
    GetCallingAppInfo(appInfo);
    printf("App package name: %s, origin: %s\n", appInfo->package_name, appInfo->origin);

    int* header_size = (int*) credentials;
    int* creds_size = (int*) (credentials + sizeof(int));
    int* icon_size_array_size = (int*) (credentials + sizeof(int) * 2);
    char* icon_ptr_array[(*icon_size_array_size) + 1];  // [icon1_start_ptr, icon2_start_ptr, ..., iconN_start_ptr, iconN_end_ptr]
    icon_ptr_array[0] = credentials + *header_size + *creds_size; // start of icon
    int icon_size_index = 0;
    while (icon_size_index < *icon_size_array_size) {
        int* curr_icon_size = (int*) (credentials + sizeof(int) * (3 + icon_size_index));
	    // printf("curr_icon_size: %d\n", *curr_icon_size);
        icon_ptr_array[icon_size_index+1] = icon_ptr_array[icon_size_index] + (*curr_icon_size); 
        ++icon_size_index;
    }
	cJSON *request_json = cJSON_Parse(request);
	cJSON *credentials_json = cJSON_Parse(credentials + *header_size);
	
	char *request_json_str = cJSON_Print(request_json);
	printf("Request: %s\n", request_json_str);
	char *creds_json_str = cJSON_Print(credentials_json);
	printf("Creds: %s\n", creds_json_str);

    // Parse request
    Matcher *head_matcher = NULL;
    int matcher_size = 0;
    cJSON *providers = cJSON_GetObjectItemCaseSensitive(request_json, "providers");
    if (cJSON_IsArray(providers)) {
        int providerSize = cJSON_GetArraySize(providers);
        int i = 0;
        while (i < providerSize) {
            cJSON *provider = cJSON_GetArrayItem(providers, i);
            if (cJSON_IsObject(provider)) {
                cJSON *selector = cJSON_GetObjectItem(provider, "selector");
                if (cJSON_IsObject(selector)) {
                    cJSON *fields = cJSON_GetObjectItem(selector, "fields");
                    if (cJSON_IsArray(fields)) {
                        int fieldSize = cJSON_GetArraySize(fields);
                        int j = 0;
                        while (j < fieldSize) {
                            cJSON *field = cJSON_GetArrayItem(fields, j);
                            if (cJSON_IsObject(field)) {
                                // Required fields. For now only name.
                                cJSON *nameField =  cJSON_GetObjectItem(field, "name");
                                char* nameFieldValue = cJSON_GetStringValue(nameField);

                                // Optional matcher fields. For now only equal.
                                if (cJSON_HasObjectItem(field, "equal")) {
                                    cJSON *equalField = cJSON_GetObjectItem(field, "equal");
                                    Matcher *prev_matcher = head_matcher;
                                    head_matcher = malloc(sizeof(Matcher));
                                    init_matcher(head_matcher, nameFieldValue, Matcher_EQUAL, equalField, prev_matcher);
                                    ++matcher_size;
                                } else {
                                    Matcher *prev_matcher = head_matcher;
                                    head_matcher = malloc(sizeof(Matcher));
                                    init_matcher(head_matcher, nameFieldValue, Matcher_NONE, NULL, prev_matcher);
                                    ++matcher_size;
                                }
                            } else {
                                printf("Not a valid field object\n");
                            }
                            ++j;
                        }
                    } else {
                        printf("Failed to find a valid `fields` field\n");
                    }
                } else {
                    printf("Failed to find a valid `selector` field\n");
                }
            } else {
                printf("Not a valid provider object\n");
            }
            ++i;
        }
    } else {
        printf("Failed to find a valid `providers` field\n");
    }

    if (head_matcher == NULL) {
        return 0;
    }

    // Match data
    cJSON *creds = cJSON_GetObjectItemCaseSensitive(credentials_json, "credentials");
    printf("Matching\n");
    if (cJSON_IsArray(creds)) {
        int credential_size = cJSON_GetArraySize(creds);
        int i = 0;
        while (i < credential_size) {
            cJSON *cred = cJSON_GetArrayItem(creds, i);
            if (cJSON_IsObject(cred)) {
                cJSON *credential = cJSON_GetObjectItem(cred, "credential");
                cJSON *cred_fields = cJSON_GetObjectItem(credential, "fields");
                int field_size = cJSON_GetArraySize(cred_fields);
                // Pre-allocate spaces to record field names and values that are matched.
                char **field_display_names = malloc(sizeof(char*) * matcher_size);
                char **field_display_values = malloc(sizeof(char*) * matcher_size);
                int field_display_names_idx = 0;
                Matcher *matcher_itr = head_matcher;
                while (matcher_itr != NULL) {
                    int matched = 0;
                    int j = 0;
                    while (j < field_size) {
                        cJSON *field = cJSON_GetArrayItem(cred_fields, j);
                        cJSON *field_name = cJSON_GetObjectItem(field, "name");
                        char* field_name_value = cJSON_GetStringValue(field_name);
                        if (strcmp(matcher_itr->name, field_name_value) == 0) {
                            if ((matcher_itr->type & 0xFF) == Matcher_NONE) {
                                // TODO: abstract into method
                                // if-change-#1
                                if (cJSON_HasObjectItem(field, "display_name")){
                                    cJSON *field_display_name = cJSON_GetObjectItem(field, "display_name");
                                    field_display_names[field_display_names_idx] = cJSON_GetStringValue(field_display_name);
                                    if (cJSON_HasObjectItem(field, "display_value")){
                                        cJSON *field_display_value = cJSON_GetObjectItem(field, "display_value");
                                        field_display_values[field_display_names_idx] = cJSON_GetStringValue(field_display_value);
                                    } else {
                                            field_display_values[field_display_names_idx] = NULL;
                                    }
                                    ++field_display_names_idx;
                                }
                                // End if-change-#1
                                matched = 1;
                            } else if ((matcher_itr->type & 0xFF) == Matcher_EQUAL) {
                                cJSON *field_value = cJSON_GetObjectItem(field, "value");
                                char* field_value_str = cJSON_GetStringValue(field_value);
                                char* matcher_value_str = cJSON_GetStringValue(matcher_itr->matcher_value);
                                if (strcmp(matcher_value_str, field_value_str) == 0) {
                                    // then-change-#1
                                    if (cJSON_HasObjectItem(field, "display_name")){
                                        cJSON *field_display_name = cJSON_GetObjectItem(field, "display_name");
                                        field_display_names[field_display_names_idx] = cJSON_GetStringValue(field_display_name);
                                        if (cJSON_HasObjectItem(field, "display_value")){
                                            cJSON *field_display_value = cJSON_GetObjectItem(field, "display_value");
                                            field_display_values[field_display_names_idx] = cJSON_GetStringValue(field_display_value);
                                        } else {
                                            field_display_values[field_display_names_idx] = NULL;
                                        }
                                        ++field_display_names_idx;
                                    }
                                    // End then-change-#1
                                    matched = 1;
                                } else {
                                    break;
                                }
                            }
                        }
                        ++j;
                    }
                    if (matched == 0) {
                        break;
                    }
                    matcher_itr = matcher_itr->next;
                }
                if (matcher_itr == NULL) { // All matcher succeeds through. The cred is a match.
                    printf("Found a match!\n");
                    cJSON *id = cJSON_GetObjectItem(cred, "id");
                    long long id_value = cJSON_GetNumberValue(id);
                    cJSON *cred_display_info = cJSON_GetObjectItem(credential, "display_info");
                    cJSON *title_json = cJSON_GetObjectItem(cred_display_info, "title");
                    char *title = cJSON_GetStringValue(title_json);
                    char *icon_start = NULL;
                    size_t icon_len = 0;
                    char *subtitle = NULL;
                    char *disclaimer = NULL;
                    char *warning = NULL;
                    if (cJSON_HasObjectItem(cred_display_info, "icon_id")){
                        cJSON *icon_id_json = cJSON_GetObjectItem(cred_display_info, "icon_id");
                        int icon_id = cJSON_GetNumberValue(icon_id_json);
                        if (icon_id >= 0 && icon_id < *icon_size_array_size) {
                            icon_start = icon_ptr_array[icon_id];
                            icon_len = icon_ptr_array[icon_id+1] - icon_start;
                        }
                    }
                    if (cJSON_HasObjectItem(cred_display_info, "subtitle")){
                        cJSON *subtitle_json = cJSON_GetObjectItem(cred_display_info, "subtitle");
                        subtitle = cJSON_GetStringValue(subtitle_json);
                    }
                    if (cJSON_HasObjectItem(cred_display_info, "disclaimer")){
                        cJSON *disclaimer_json = cJSON_GetObjectItem(cred_display_info, "disclaimer");
                        disclaimer = cJSON_GetStringValue(disclaimer_json);
                    }
                    if (cJSON_HasObjectItem(cred_display_info, "warning")){
                        cJSON *warning_json = cJSON_GetObjectItem(cred_display_info, "warning");
                        warning = cJSON_GetStringValue(warning_json);
                    }
                    printf("Adding entry with title %s, icon_len!\n", title);
                    AddEntry(id_value, icon_start, icon_len, title, subtitle, disclaimer, warning);

                    int k = 0;
                    while (k < field_display_names_idx) {
                        printf("Adding field with display name %s!\n", field_display_names[k]);
                        AddField(id_value, field_display_names[k], field_display_values[k]);
                        ++k;
                    }
                }
            } else {
                printf("Not a valid credential object\n");
            }
            ++i;
        }
    } else {
        printf("Failed to find a valid `credentials` field\n");
    }

	//cJSON_Delete(request_json);
	//cJSON_Delete(credentials_json);
	return 0;
}
