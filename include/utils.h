/*
 * utils.h — Yardımcı Fonksiyonlar
 * Dinamik dizi, hash map, string yardımcıları.
 */
#ifndef UTILS_H
#define UTILS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ========== Dinamik Dizi (Generic) ========== */
typedef struct {
    void  *data;
    int    count;
    int    capacity;
    int    item_size;
} DynArray;

void  dynarray_init(DynArray *arr, int item_size, int initial_cap);
void *dynarray_push(DynArray *arr, const void *item);
void *dynarray_get(DynArray *arr, int index);
void  dynarray_clear(DynArray *arr);
void  dynarray_free(DynArray *arr);

/* ========== Basit Hash Map (string key → string value) ========== */
#define HASHMAP_BUCKETS 4096

typedef struct HashEntry {
    char *key;
    char *value;
    struct HashEntry *next;
} HashEntry;

typedef struct {
    HashEntry *buckets[HASHMAP_BUCKETS];
    int count;
} HashMap;

void        hashmap_init(HashMap *map);
void        hashmap_put(HashMap *map, const char *key, const char *value);
const char *hashmap_get(const HashMap *map, const char *key);
void        hashmap_free(HashMap *map);

/* ========== String Yardımcıları ========== */
void  str_trim(char *s);
void  str_upper(char *s);
int   str_starts_with(const char *s, const char *prefix);
int   str_contains(const char *haystack, const char *needle);
int   str_contains_ci(const char *haystack, const char *needle); /* case-insensitive */
char *str_dup(const char *s);

/* ========== Zaman Yardımcıları ========== */
void  time_now_iso(char *buf, int len);
void  time_now_hms(char *buf, int len);

/* ========== IP Yardımcıları ========== */
int   ip_to_int(const char *ip);
void  int_to_ip(int ip_int, char *buf, int len);
int   is_private_ip(const char *ip);

#endif /* UTILS_H */
