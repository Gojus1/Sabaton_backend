#include "shamir.h"

// Example usage:
// ./a.exe -decypher -shamir -alph "AĄBCČDEĘĖFGHIĮYJKLMNOPRSŠTUŲŪVZŽ" -frag "324171335,242310513,212364309|48482677,342190219,101949621|386442899"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

/* Safe modular inverse using Extended Euclidean Algorithm */
static uint32_t shamir_modinv(uint32_t a, uint32_t p) {
    if (a == 0 || p == 0) return 0;
    int64_t t = 0, newt = 1;
    int64_t r = p, newr = a;

    while (newr != 0) {
        int64_t q = r / newr;
        int64_t tmp = newt; newt = t - q * newt; t = tmp;
        tmp = newr; newr = r - q * newr; r = tmp;
    }

    if (r > 1) return 0; // not invertible
    if (t < 0) t += p;
    return (uint32_t)t;
}

/* Recover secret using Lagrange interpolation mod p safely */
static uint32_t shamir_recover_secret(uint32_t p, const uint32_t* x, const uint32_t* s, size_t n) {
    if (!p || !x || !s || n < 2) return 0;

    uint64_t secret = 0;

    for (size_t i = 0; i < n; ++i) {
        uint64_t li = 1;

        for (size_t j = 0; j < n; ++j) {
            if (i == j) continue;

            uint64_t num = (p + p - x[j]) % p;
            uint64_t den = (p + x[i] - x[j]) % p;

            if (den == 0) return 0; // prevent division by zero
            uint32_t inv = shamir_modinv((uint32_t)den, p);
            if (inv == 0) return 0; // denominator not invertible

            li = (li * num) % p;
            li = (li * inv) % p;
        }

        secret = (secret + (uint64_t)s[i] * li) % p;
    }

    return (uint32_t)secret;
}

/* Backtracking decode function */
static void decode_backtrack_mem(const char* num, size_t num_len, size_t pos,
    const char* alph[], size_t alph_len,
    char* out, size_t out_pos,
    char** results, size_t* result_count, size_t max_results)
{
    if (pos == num_len) {
        out[out_pos] = '\0';
        if (*result_count < max_results) {
            results[*result_count] = strdup(out);
            (*result_count)++;
        }
        return;
    }

    if (num[pos] == '0') {
        decode_backtrack_mem(num, num_len, pos + 1, alph, alph_len, out, out_pos, results, result_count, max_results);
        return;
    }

    for (int digits = 1; digits <= 2; ++digits) {
        if (pos + digits > num_len) continue;
        int value = 0;
        for (int i = 0; i < digits; ++i)
            value = value * 10 + (num[pos + i] - '0');

        if (value >= 1 && value <= (int)alph_len) {
            const char* ch = alph[value - 1];
            size_t l = strlen(ch);
            memcpy(out + out_pos, ch, l);
            decode_backtrack_mem(num, num_len, pos + digits, alph, alph_len, out, out_pos + l, results, result_count, max_results);
        }
    }
}

/* Main entry function */
const char* shamirEntryMem(const char* alph_str, const char* encText, const char* frag) {
    (void)encText;
    if (!alph_str || !*alph_str) return strdup("[no alph]");

    /* Convert alphabet string to array of UTF-8 chars */
    const char* alph[64];
    size_t alph_len = 0;
    char buf[8];
    const char* p = alph_str;
    while (*p) {
        int bytes = 1;
        unsigned char c = (unsigned char)p[0];
        if (c >= 0xC0) {
            if (c < 0xE0) bytes = 2;
            else if (c < 0xF0) bytes = 3;
            else bytes = 4;
        }
        memcpy(buf, p, bytes);
        buf[bytes] = '\0';
        alph[alph_len++] = strdup(buf);
        p += bytes;
    }

    uint32_t p_val = 0, x[3] = {0}, s[3] = {0};

    if (frag && *frag) {
        char* copy = strdup(frag);
        char* part = strtok(copy, "|");
        int stage = 0;
        while (part) {
            if (stage == 0) {
                int tmp[3], c = 0;
                parseCSV(part, tmp, &c);
                if (c == 3) for (int i = 0; i < 3; ++i) x[i] = (uint32_t)tmp[i];
            } else if (stage == 1) {
                int tmp[3], c = 0;
                parseCSV(part, tmp, &c);
                if (c == 3) for (int i = 0; i < 3; ++i) s[i] = (uint32_t)tmp[i];
            } else if (stage == 2) {
                p_val = (uint32_t)strtoul(part, NULL, 10);
            }
            part = strtok(NULL, "|");
            stage++;
        }
        free(copy);
    }

    /* Recover secret safely */
    uint32_t secret = shamir_recover_secret(p_val, x, s, 3);
    if (secret == 0) return strdup("[invalid input or recovery failed]");

    char numbuf[32];
    snprintf(numbuf, sizeof(numbuf), "%u", secret);

    /* Decode backtrack */
    char* results[1000];
    size_t result_count = 0;
    char outbuf[512];
    decode_backtrack_mem(numbuf, strlen(numbuf), 0, alph, alph_len, outbuf, 0, results, &result_count, 1000);

    /* Combine results */
    size_t total_len = 0;
    for (size_t i = 0; i < result_count; ++i) total_len += strlen(results[i]) + 1;

    char* final = malloc(total_len + 1);
    if (!final) {
        for (size_t i = 0; i < result_count; ++i) free(results[i]);
        for (size_t i = 0; i < alph_len; ++i) free((void*)alph[i]);
        return strdup("[memory error]");
    }

    final[0] = '\0';
    for (size_t i = 0; i < result_count; ++i) {
        strcat(final, results[i]);
        if (i + 1 < result_count) strcat(final, "\n");
        free(results[i]);
    }

    for (size_t i = 0; i < alph_len; ++i) free((void*)alph[i]);

    return final; /* caller must free */
}