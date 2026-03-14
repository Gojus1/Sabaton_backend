#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "rabin.h"

#define MAX_DIGITS 1024
#define MAX_OUTPUT 4096
#define MAX_ALPH 64
#define MAX_MSG 256

/* Convert BigInt root to text safely */
static char* number2text(const BigInt* M, const char* alphUtf8)
{
    if (!M || !alphUtf8)
        return NULL;

    char* dec = biToAlphabet(M, "0123456789", 10);
    if (!dec) return NULL;

    size_t len = strlen(dec);

    if (len > MAX_DIGITS)
    {
        free(dec);
        return strdup("[number too large]");
    }

    if (len % 2 != 0)
    {
        char* tmp = malloc(len + 2);
        if (!tmp)
        {
            free(dec);
            return NULL;
        }

        tmp[0] = '0';
        memcpy(tmp + 1, dec, len + 1);

        free(dec);
        dec = tmp;
        len++;
    }

    uint32_t alph_cps[MAX_ALPH];
    int base = utf8_to_u32(alphUtf8, alph_cps, MAX_ALPH);

    if (base <= 0 || base > MAX_ALPH)
    {
        free(dec);
        return strdup("[invalid alphabet]");
    }

    uint32_t msg_cps[MAX_MSG];
    int count = 0;

    for (size_t i = 0; i + 1 < len && count < MAX_MSG; i += 2)
    {
        char c1 = dec[i];
        char c2 = dec[i+1];

        if (c1 < '0' || c1 > '9' || c2 < '0' || c2 > '9')
            continue;

        int code = (c1 - '0') * 10 + (c2 - '0');

        if (code <= 0 || code > base)
            continue;

        msg_cps[count++] = alph_cps[code - 1];
    }

    free(dec);

    char* out = malloc((size_t)count * 4 + 1);
    if (!out)
        return NULL;

    u32_to_utf8(msg_cps, count, out, count * 4 + 1);

    return out;
}

/* sqrt mod p */
void __sqrt(BigInt *out, const BigInt *c, const BigInt *p)
{
    BigInt one, exp, tmp, cmod;

    biMod(&cmod, c, p);

    biFromU32(&one, 1);
    biAdd(&tmp, p, &one);
    biDivU32(&exp, &tmp, 4);

    biPowMod(out, &cmod, &exp, p);

    biClear(&one);
    biClear(&exp);
    biClear(&tmp);
    biClear(&cmod);
}

/* CRT recombination */
int decrypt_roots(const BigInt *c,
                  const BigInt *p,
                  const BigInt *q,
                  BigInt roots[4])
{
    BigInt mp, mq, yp, yq, n;

    __sqrt(&mp, c, p);
    __sqrt(&mq, c, q);

    if (!biModInv(&yp, p, q))
    {
        biClear(&mp); biClear(&mq);
        return 0;
    }

    if (!biModInv(&yq, q, p))
    {
        biClear(&mp); biClear(&mq);
        biClear(&yp);
        return 0;
    }

    biMul(&n, p, q);

    int idx = 0;

    for (int sp = 0; sp < 2; sp++)
    {
        BigInt rp;

        if (sp == 0) biCopy(&rp, &mp);
        else biSub(&rp, p, &mp);

        for (int sq = 0; sq < 2; sq++)
        {
            BigInt rq, t1, t2, sum, res;

            if (sq == 0) biCopy(&rq, &mq);
            else biSub(&rq, q, &mq);

            biMul(&t1, &rp, q);
            biMul(&t1, &t1, &yq);

            biMul(&t2, &rq, p);
            biMul(&t2, &t2, &yp);

            biAdd(&sum, &t1, &t2);
            biMod(&res, &sum, &n);

            biCopy(&roots[idx++], &res);

            biClear(&rq); biClear(&t1);
            biClear(&t2); biClear(&sum);
            biClear(&res);
        }

        biClear(&rp);
    }

    biClear(&mp); biClear(&mq);
    biClear(&yp); biClear(&yq);
    biClear(&n);

    return 4;
}

char* rabinEntry(const char* alph,
                 const char* encText,
                 const char* frag)
{
    (void)encText;

    if (!frag || !*frag)
        return strdup("ERROR: missing fragment");

    char* tmp = strdup(frag);
    if (!tmp)
        return strdup("ERROR: out of memory");

    char* c_str = strtok(tmp, ",");
    char* p_str = strtok(NULL, ",");
    char* q_str = strtok(NULL, ",");

    if (!c_str || !p_str || !q_str)
    {
        free(tmp);
        return strdup("ERROR: expected frag = c|p|q");
    }

    if (strlen(c_str) > MAX_DIGITS ||
        strlen(p_str) > MAX_DIGITS ||
        strlen(q_str) > MAX_DIGITS)
    {
        free(tmp);
        return strdup("ERROR: numbers too large");
    }

    BigInt c, p, q;

    biFromDec(&c, c_str);
    biFromDec(&p, p_str);
    biFromDec(&q, q_str);

    BigInt roots[4];

    int cnt = decrypt_roots(&c, &p, &q, roots);

    biClear(&c);
    biClear(&p);
    biClear(&q);

    if (cnt <= 0)
    {
        free(tmp);
        return strdup("ERROR: Rabin decryption failed");
    }

    char* out = malloc(MAX_OUTPUT);
    if (!out)
    {
        free(tmp);
        return strdup("ERROR: out of memory");
    }

    size_t pos = 0;
    out[0] = '\0';

    for (int i = 0; i < cnt; i++)
    {
        char numbuf[512];
        biToDecString(&roots[i], numbuf, sizeof(numbuf));

        char* text = number2text(&roots[i], alph);
        if (!text)
            text = strdup("(decode error)");

        char line[1024];
        snprintf(line, sizeof(line),
                 "Root %d = %s\nText   = %s\n\n",
                 i + 1, numbuf, text);

        size_t l = strlen(line);

        if (pos + l < MAX_OUTPUT)
        {
            memcpy(out + pos, line, l);
            pos += l;
            out[pos] = '\0';
        }

        free(text);
        biClear(&roots[i]);
    }

    free(tmp);
    return out;
}