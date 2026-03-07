#include "rsa.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Computes gcd(a,b) and finds x,y such that a*x + b*y = gcd(a,b)
static long long egcd_ll(long long a, long long b, long long* x, long long* y) {
    if (b == 0) {
        if (x) *x = 1;
        if (y) *y = 0;
        return a;
    }
    long long x1, y1;
    long long g = egcd_ll(b, a % b, &x1, &y1);
    if (x) *x = y1;
    if (y) *y = x1 - (a / b) * y1;
    return g;
}

// Converts a signed long long to a BigInt (absolute value)
static void biFromLL(BigInt* x, long long v) {
    if (v < 0) v = -v;       // take absolute value
    biFromU32(x, (uint32_t)v);  // delegate to biFromU32
}

static char* rsaDecodeDecimalToText(const BigInt* M, const char* alphUtf8) {
    char* dec = biToAlphabet(M, "0123456789", 10);
    if (!dec) return NULL;

    size_t len = strlen(dec);
    if (len % 2 != 0) {
        char* tmp = malloc(len + 2);
        if (!tmp) { free(dec); return NULL; }
        tmp[0] = '0';
        memcpy(tmp + 1, dec, len + 1);
        free(dec);
        dec = tmp;
        len++;
    }

    uint32_t alph_cps[64];
    int base = utf8_to_u32(alphUtf8, alph_cps, 64);   
    if (base <= 0) { free(dec); return strdup("[invalid alphabet]"); }

    uint32_t msg_cps[256];
    int count = 0;
    for (size_t i = 0; i < len && count < 256; i += 2) {
        int d1 = dec[i]   - '0';
        int d2 = dec[i+1] - '0';
        if (d1 < 0 || d1 > 9 || d2 < 0 || d2 > 9) continue;

        int code = d1 * 10 + d2;  
        if (code <= 0 || code > base) continue;

        msg_cps[count++] = alph_cps[code - 1];  
    }

    free(dec);

    char* out = malloc((size_t)count * 4 + 1);
    if (!out) return strdup("[decode failed]");
    u32_to_utf8(msg_cps, count, out, (int)(count * 4 + 1));
    return out;
}

static const char* rsaDeriveD(const char* n_str,
                              const char* e1_str,
                              const char* d1_str,
                              const char* e2_str)
{
    BigInt N, E1, D1, E2, K, one, Phi, D2;
    char* result = NULL;

    biFromDec(&N,  n_str);
    biFromDec(&E1, e1_str);
    biFromDec(&D1, d1_str);
    biFromDec(&E2, e2_str);

    biMul(&K, &E1, &D1);
    biFromU32(&one, 1);
    biSub(&K, &K, &one);

    int found_phi = 0;
    for (unsigned int k = 1; k <= 456; ++k) {
        if (biModU32(&K, k) != 0) continue;
        biDivU32(&Phi, &K, k); 
        if (biCmp(&Phi, &N) < 0) {
            found_phi = 1;
            break;              
        }
        biClear(&Phi);
    }

    if (!found_phi) {
        result = strdup("RSA derive error: could not recover phi(n) from e1,d1");
        goto cleanup;
    }

    if (!biModInv(&D2, &E2, &Phi)) {
        result = strdup("RSA derive error: e2 has no inverse mod phi(n)");
        goto cleanup;
    }

    char* d2_str = biToAlphabet(&D2, "0123456789", 10);
    if (!d2_str) {
        result = strdup("RSA derive error: failed to convert d to decimal");
    } else {
        result = d2_str; // already heap-allocated
    }

cleanup:
    biClear(&N); biClear(&E1); biClear(&D1); biClear(&E2);
    biClear(&K); biClear(&one); biClear(&Phi); biClear(&D2);
    return result;
}

const char* rsaDecryption(const char* alph, const FragMap* vars, const char* encText){
    if (!vars || vars->count < 3) {
        return strdup("RSA error: need at least 3 values (n,e,d) for simple decryption");
    }

    const char* n_str = vars->items[0].value;  
    const char* d_str = vars->items[2].value;  
    const char* c_str = encText;

    BigInt N, D, C, M;
    biFromDec(&N, n_str);
    biFromDec(&D, d_str);
    biFromDec(&C, c_str);

    biPowMod(&M, &C, &D, &N);

    char* plaintext = rsaDecodeDecimalToText(&M, alph);

    biClear(&N); biClear(&D); biClear(&C); biClear(&M);

    return plaintext ? plaintext : strdup("RSA error: decode failed");
}

const char* rsaModuloAttack(const char* alph,
                            const FragMap* blocks,
                            size_t block_count,
                            const char* encText)
{
    if (!blocks || block_count < 2) {
        return strdup("RSA mod error: need at least 2 blocks (e,c) with common n");
    }

    const char* n_str = fragmapGet(&blocks[0], "n");
    if (!n_str || !*n_str) return strdup("RSA mod error: missing modulus n in frag");

    const FragMap* b1 = &blocks[0];
    const FragMap* b2 = &blocks[1];

    const char* e1_str = fragmapGet(b1, "e");
    const char* c1_str = fragmapGet(b1, "c");
    const char* e2_str = fragmapGet(b2, "e");
    const char* c2_str = fragmapGet(b2, "c");

    if (!e1_str || !c1_str || !e2_str || !c2_str)
        return strdup("RSA mod error: each block must have e:... and c:...");

    long long e1 = strtoll(e1_str, NULL, 10);
    long long e2 = strtoll(e2_str, NULL, 10);
    long long s, t;
    long long g = egcd_ll(e1, e2, &s, &t);

    if (g != 1 && g != -1)
        return strdup("RSA mod error: exponents are not coprime, common modulus attack fails");
    if (g == -1) { s = -s; t = -t; }

    BigInt N, C1, C2, term1, term2, M, tmp;
    biFromDec(&N, n_str);
    biFromDec(&C1, c1_str);
    biFromDec(&C2, c2_str);

    if (s >= 0) { BigInt eS; biFromLL(&eS, s); biPowMod(&term1, &C1, &eS, &N); biClear(&eS); }
    else {
        BigInt inv1, eS; if (!biModInv(&inv1, &C1, &N)) { biClear(&N); biClear(&C1); biClear(&C2); biClear(&term1); return strdup("RSA mod error: inverse of C1 does not exist mod n"); }
        biFromLL(&eS, -s); biPowMod(&term1, &inv1, &eS, &N); biClear(&inv1); biClear(&eS);
    }

    if (t >= 0) { BigInt eT; biFromLL(&eT, t); biPowMod(&term2, &C2, &eT, &N); biClear(&eT); }
    else {
        BigInt inv2, eT; if (!biModInv(&inv2, &C2, &N)) { biClear(&N); biClear(&C1); biClear(&C2); biClear(&term1); biClear(&term2); return strdup("RSA mod error: inverse of C2 does not exist mod n"); }
        biFromLL(&eT, -t); biPowMod(&term2, &inv2, &eT, &N); biClear(&inv2); biClear(&eT);
    }

    biMulMod(&tmp, &term1, &term2, &N);
    biCopy(&M, &tmp);

    char* plaintext = rsaDecodeDecimalToText(&M, alph);

    biClear(&N); biClear(&C1); biClear(&C2); biClear(&term1); biClear(&term2); biClear(&M); biClear(&tmp);

    return plaintext ? plaintext : strdup("RSA mod error: decode failed");
}

const char* rsaEntry(const char* alph, const char* encText, const char* frag)
{
    if (!frag || !*frag) return strdup("[no frag]");

    int is_mod    = 0;
    int is_derive = 0;
    const char *spec = frag;

    if (strncmp(frag, "mod:", 4) == 0) { 
        is_mod = 1; 
        spec = frag + 4; 
    } else if (strncmp(frag, "derive:", 7) == 0) { 
        is_derive = 1; 
        spec = frag + 7; 
    }

    if (is_mod) {
        // leave unchanged
        // ...
        return strdup("RSA mod: not changed in this snippet");
    } 
    else if (is_derive) {
        // unchanged
        return strdup("RSA derive: not changed in this snippet");
    } 
    else {
        // --- NEW: accept plain num,num,num ---
        char* numbers[3] = {0};
        char* copy = strdup(spec);
        if (!copy) return strdup("RSA error: OOM");

        char* token = strtok(copy, ",");
        int i = 0;
        while (token && i < 3) {
            numbers[i++] = token;
            token = strtok(NULL, ",");
        }

        if (i < 3) { free(copy); return strdup("RSA error: fragment must have 3 numbers"); }

        // call rsaDecryption directly
        BigInt N, D, C, M;
        biFromDec(&N, numbers[0]);
        biFromDec(&D, numbers[2]);
        biFromDec(&C, encText);
        biPowMod(&M, &C, &D, &N);

        char* plaintext = rsaDecodeDecimalToText(&M, alph);

        biClear(&N); biClear(&D); biClear(&C); biClear(&M);
        free(copy);

        return plaintext ? plaintext : strdup("RSA error: decode failed");
    }
}