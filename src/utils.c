/*
 * utils.c — Yardımcı Fonksiyonlar Uygulaması
 */
#include "utils.h"
#include <ctype.h>
#include <time.h>
#include <string.h>

/* ========== Dinamik Dizi ========== */
void dynarray_init(DynArray *arr, int item_size, int initial_cap) {
    arr->item_size = item_size;
    arr->count = 0;
    arr->capacity = initial_cap > 0 ? initial_cap : 16;
    arr->data = malloc(arr->capacity * arr->item_size);
}

void *dynarray_push(DynArray *arr, const void *item) {
    if (arr->count >= arr->capacity) {
        arr->capacity *= 2;
        arr->data = realloc(arr->data, arr->capacity * arr->item_size);
    }
    void *slot = (char *)arr->data + arr->count * arr->item_size;
    memcpy(slot, item, arr->item_size);
    arr->count++;
    return slot;
}

void *dynarray_get(DynArray *arr, int index) {
    if (index < 0 || index >= arr->count) return NULL;
    return (char *)arr->data + index * arr->item_size;
}

void dynarray_clear(DynArray *arr) {
    arr->count = 0;
}

void dynarray_free(DynArray *arr) {
    if (arr->data) { free(arr->data); arr->data = NULL; }
    arr->count = 0;
    arr->capacity = 0;
}

/* ========== Hash Map ========== */
static unsigned int _hash_string(const char *key) {
    unsigned int h = 5381;
    int c;
    while ((c = *key++))
        h = ((h << 5) + h) + c;
    return h % HASHMAP_BUCKETS;
}

void hashmap_init(HashMap *map) {
    memset(map->buckets, 0, sizeof(map->buckets));
    map->count = 0;
}

void hashmap_put(HashMap *map, const char *key, const char *value) {
    unsigned int idx = _hash_string(key);
    
    /* Mevcut entry'yi güncelle */
    HashEntry *entry = map->buckets[idx];
    while (entry) {
        if (strcmp(entry->key, key) == 0) {
            free(entry->value);
            entry->value = strdup(value);
            return;
        }
        entry = entry->next;
    }
    
    /* Yeni entry ekle */
    HashEntry *new_entry = (HashEntry *)malloc(sizeof(HashEntry));
    new_entry->key = strdup(key);
    new_entry->value = strdup(value);
    new_entry->next = map->buckets[idx];
    map->buckets[idx] = new_entry;
    map->count++;
}

const char *hashmap_get(const HashMap *map, const char *key) {
    unsigned int idx = _hash_string(key);
    HashEntry *entry = map->buckets[idx];
    while (entry) {
        if (strcmp(entry->key, key) == 0)
            return entry->value;
        entry = entry->next;
    }
    return NULL;
}

void hashmap_free(HashMap *map) {
    for (int i = 0; i < HASHMAP_BUCKETS; i++) {
        HashEntry *entry = map->buckets[i];
        while (entry) {
            HashEntry *next = entry->next;
            free(entry->key);
            free(entry->value);
            free(entry);
            entry = next;
        }
        map->buckets[i] = NULL;
    }
    map->count = 0;
}

/* ========== String Yardımcıları ========== */
void str_trim(char *s) {
    /* Baştaki boşlukları kaldır */
    char *start = s;
    while (*start && isspace((unsigned char)*start)) start++;
    if (start != s) memmove(s, start, strlen(start) + 1);
    
    /* Sondaki boşlukları kaldır */
    int len = strlen(s);
    while (len > 0 && isspace((unsigned char)s[len - 1])) {
        s[--len] = '\0';
    }
}

void str_upper(char *s) {
    for (; *s; s++) *s = toupper((unsigned char)*s);
}

int str_starts_with(const char *s, const char *prefix) {
    return strncmp(s, prefix, strlen(prefix)) == 0;
}

int str_contains(const char *haystack, const char *needle) {
    return strstr(haystack, needle) != NULL;
}

int str_contains_ci(const char *haystack, const char *needle) {
    if (!haystack || !needle) return 0;
    int h_len = strlen(haystack);
    int n_len = strlen(needle);
    if (n_len > h_len) return 0;
    
    for (int i = 0; i <= h_len - n_len; i++) {
        int match = 1;
        for (int j = 0; j < n_len; j++) {
            if (tolower((unsigned char)haystack[i + j]) != tolower((unsigned char)needle[j])) {
                match = 0;
                break;
            }
        }
        if (match) return 1;
    }
    return 0;
}

char *str_dup(const char *s) {
    if (!s) return NULL;
    int len = strlen(s);
    char *d = (char *)malloc(len + 1);
    memcpy(d, s, len + 1);
    return d;
}

/* ========== Zaman Yardımcıları ========== */
void time_now_iso(char *buf, int len) {
    time_t t = time(NULL);
    struct tm *tm = localtime(&t);
    strftime(buf, len, "%Y-%m-%dT%H:%M:%S", tm);
}

void time_now_hms(char *buf, int len) {
    time_t t = time(NULL);
    struct tm *tm = localtime(&t);
    strftime(buf, len, "%H:%M:%S", tm);
}

/* ========== IP Yardımcıları ========== */
int ip_to_int(const char *ip) {
    int a, b, c, d;
    if (sscanf(ip, "%d.%d.%d.%d", &a, &b, &c, &d) == 4) {
        return (a << 24) | (b << 16) | (c << 8) | d;
    }
    return 0;
}

void int_to_ip(int ip_int, char *buf, int len) {
    snprintf(buf, len, "%d.%d.%d.%d",
             (ip_int >> 24) & 0xFF, (ip_int >> 16) & 0xFF,
             (ip_int >> 8) & 0xFF, ip_int & 0xFF);
}

int is_private_ip(const char *ip) {
    int a, b;
    if (sscanf(ip, "%d.%d", &a, &b) < 1) return 0;
    if (a == 10) return 1;                      /* 10.0.0.0/8 */
    if (a == 172 && b >= 16 && b <= 31) return 1; /* 172.16.0.0/12 */
    if (a == 192 && b == 168) return 1;         /* 192.168.0.0/16 */
    if (a == 127) return 1;                     /* 127.0.0.0/8 */
    return 0;
}
