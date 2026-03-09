#include "stream.h"
#include "../enhancements/lith/lithuanian.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define MAX_CIPHERTEXT 4096

/* Reverse 8-bit integer bit order */
static uint8_t reverse_bits8(uint8_t x){
    x = (x & 0xF0) >> 4 | (x & 0x0F) << 4;
    x = (x & 0xCC) >> 2 | (x & 0x33) << 2;
    x = (x & 0xAA) >> 1 | (x & 0x55) << 1;
    return x;
}

/* LFSR implementations */

static uint8_t lfsr_next_bit_right(uint8_t *state, uint8_t taps){
    if(!state) return 0;
    uint8_t s = *state;
    uint8_t out = s & 1u;

    uint8_t x = s & taps;
    x ^= x >> 4; x ^= x >> 2; x ^= x >> 1;

    uint8_t newbit = x & 1u;
    s = (s >> 1) | (uint8_t)(newbit << 7);

    *state = s;
    return out;
}

static uint8_t lfsr_next_bit_left(uint8_t *state, uint8_t taps){
    if(!state) return 0;
    uint8_t s = *state;
    uint8_t out = (s >> 7) & 1u;

    uint8_t x = s & taps;
    x ^= x >> 4; x ^= x >> 2; x ^= x >> 1;

    uint8_t newbit = x & 1u;
    s = (uint8_t)((s << 1) | newbit);

    *state = s;
    return out;
}

typedef uint8_t (*next_bit_fn)(uint8_t*, uint8_t);

/* collect 8 bits into byte */
static uint8_t lfsr_next_byte(uint8_t *state, uint8_t taps, next_bit_fn f, int msb_first){
    if(!state || !f) return 0;

    uint8_t b = 0;

    if(msb_first){
        for(int i=0;i<8;i++){
            uint8_t bit = f(state,taps)&1u;
            b = (b<<1)|bit;
        }
    }else{
        for(int i=0;i<8;i++){
            uint8_t bit = f(state,taps)&1u;
            b |= (bit<<i);
        }
    }

    return b;
}

/* decrypt using one LFSR variant */

static char* decrypt_with_variant(
        const int* cbytes,
        int n,
        uint8_t taps,
        uint8_t init_state,
        int shift_right,
        int msb_first,
        const char* alph)
{
    if(!cbytes || n<=0) return NULL;

    char* out = malloc((size_t)n+1);
    if(!out) return NULL;

    uint8_t st = init_state;
    next_bit_fn f = shift_right ? lfsr_next_bit_right : lfsr_next_bit_left;

    for(int i=0;i<n;i++){

        uint8_t ks = lfsr_next_byte(&st,taps,f,msb_first);
        uint8_t p = ((uint8_t)cbytes[i]) ^ ks;

        int ok=0;

        if(alph){
            for(const char* q=alph;*q;q++){
                if((unsigned char)*q==p){
                    ok=1;
                    break;
                }
            }
        }else{
            if((p>='A' && p<='Z') || p==' ') ok=1;
        }

        out[i] = ok ? (char)p : '?';
    }

    out[n]='\0';
    return out;
}

/* =========================
   STREAM ENTRY
   ========================= */

const char* streamEntry(const char* alph,const char* encText,const char* frag){

    if(!encText || !*encText)
        return strdup("[no ciphertext]");

    if(!frag || !*frag)
        return strdup("[no frag]");

    int bigN=0;
    int* cbytes = parse_frag_array(encText,&bigN);

    if(!cbytes || bigN<=0){
        if(cbytes) free(cbytes);
        return strdup("[invalid ciphertext]");
    }

    if(bigN>MAX_CIPHERTEXT){
        free(cbytes);
        return strdup("[ciphertext too large]");
    }

    const char* allowed_alph =
        (alph && *alph) ? alph : "ABCDEFGHIJKLMNOPQRSTUVWXYZ ";

    const char* s = frag;

    if(strncmp(s,"lfsr:",5)==0)
        s+=5;

    char tmp[128];
    strncpy(tmp,s,sizeof(tmp)-1);
    tmp[sizeof(tmp)-1]='\0';

    char* tokN = strtok(tmp,";");
    char* tok2 = strtok(NULL,";");

    if(!tokN){
        free(cbytes);
        return strdup("[invalid frag]");
    }

    int N = atoi(tokN);

    if(N!=8){
        free(cbytes);
        return strdup("[only 8-bit LFSR supported]");
    }

    const char* known_prefix =
        (tok2 && strcmp(tok2,"brute")!=0) ? tok2 : NULL;

    /* brute-force search */

    for(int taps=1;taps<256;taps++){

        for(int rev=0;rev<2;rev++){

            uint8_t taps_used =
                rev ? reverse_bits8((uint8_t)taps):(uint8_t)taps;

            for(int state=1;state<256;state++){

                for(int shift=0;shift<2;shift++){

                    for(int msb=0;msb<2;msb++){

                        char* dec =
                            decrypt_with_variant(
                                cbytes,bigN,
                                taps_used,
                                (uint8_t)state,
                                shift,
                                msb,
                                allowed_alph);

                        if(!dec) continue;

                        int ok=1;

                        for(int i=0;i<bigN;i++){
                            if(dec[i]=='?'){
                                ok=0;
                                break;
                            }
                        }

                        if(ok && (!known_prefix ||
                           strncmp(dec,known_prefix,
                           strlen(known_prefix))==0)){

                            free(cbytes);
                            return dec;
                        }

                        free(dec);
                    }
                }
            }
        }
    }

    free(cbytes);
    return strdup("[no candidate found]");
}