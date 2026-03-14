#include "rsa.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#define MAX_INPUT_RSA 256

/* ---------------- safe helpers ---------------- */

static long long safe_strtoll(const char* s, int* ok)
{
    if(!s || !*s){ *ok=0; return 0; }

    char* end=NULL;
    long long v=strtoll(s,&end,10);

    if(end==s || *end!='\0'){
        *ok=0;
        return 0;
    }

    *ok=1;
    return v;
}

/* extended gcd */
static long long egcd_ll(long long a,long long b,long long* x,long long* y)
{
    if(b==0){
        if(x) *x=1;
        if(y) *y=0;
        return a;
    }

    long long x1,y1;
    long long g = egcd_ll(b,a%b,&x1,&y1);

    if(x) *x=y1;
    if(y) *y=x1-(a/b)*y1;

    return g;
}

static void biFromLL(BigInt* x,long long v)
{
    if(v<0) v=-v;
    biFromU32(x,(uint32_t)v);
}

/* ---------------- decode helper ---------------- */

static char* rsaDecodeDecimalToText(const BigInt* M,const char* alphUtf8)
{
    if(!M) return strdup("[RSA decode error]");

    if(!alphUtf8 || !*alphUtf8)
        alphUtf8="ABCDEFGHIJKLMNOPQRSTUVWXYZ ";

    char* dec = biToAlphabet(M,"0123456789",10);
    if(!dec) return strdup("[RSA decode failed]");

    size_t len=strlen(dec);

    if(len%2!=0){
        char* tmp=malloc(len+2);
        if(!tmp){ free(dec); return strdup("[OOM]"); }

        tmp[0]='0';
        memcpy(tmp+1,dec,len+1);
        free(dec);
        dec=tmp;
        len++;
    }

    uint32_t alph_cps[128];
    int base=utf8_to_u32(alphUtf8,alph_cps,128);

    if(base<=0){
        free(dec);
        return strdup("[invalid alphabet]");
    }

    uint32_t msg_cps[512];
    int count=0;

    for(size_t i=0;i<len && count<512;i+=2){

        int d1=dec[i]-'0';
        int d2=dec[i+1]-'0';

        if(d1<0||d1>9||d2<0||d2>9)
            continue;

        int code=d1*10+d2;

        if(code<=0 || code>base)
            continue;

        msg_cps[count++]=alph_cps[code-1];
    }

    free(dec);

    char* out=malloc(count*4+1);
    if(!out) return strdup("[OOM]");

    u32_to_utf8(msg_cps,count,out,count*4+1);

    return out;
}

/* ---------------- simple RSA decrypt ---------------- */

const char* rsaDecryption(const char* alph,const FragMap* vars,const char* encText)
{
    if(!vars || vars->count<3)
        return strdup("RSA error: need n,e,d");

    if(!encText || strlen(encText)>MAX_INPUT_RSA)
        return strdup("RSA error: invalid ciphertext");

    const char* n_str = vars->items[0].value;
    const char* d_str = vars->items[2].value;

    if(!n_str || !d_str)
        return strdup("RSA error: missing parameters");

    BigInt N,D,C,M;

    biFromDec(&N,n_str);
    biFromDec(&D,d_str);
    biFromDec(&C,encText);

    biPowMod(&M,&C,&D,&N);

    char* plaintext = rsaDecodeDecimalToText(&M,alph);

    biClear(&N);
    biClear(&D);
    biClear(&C);
    biClear(&M);

    if(!plaintext)
        return strdup("RSA error: decode failed");

    return plaintext;
}

/* ---------------- common modulus attack ---------------- */

const char* rsaModuloAttack(
        const char* alph,
        const FragMap* blocks,
        size_t block_count,
        const char* encText)
{
    if(!blocks || block_count<2)
        return strdup("RSA mod error: need >=2 blocks");

    const char* n_str = fragmapGet(&blocks[0],"n");
    if(!n_str)
        return strdup("RSA mod error: missing n");

    const char* e1_str=fragmapGet(&blocks[0],"e");
    const char* c1_str=fragmapGet(&blocks[0],"c");
    const char* e2_str=fragmapGet(&blocks[1],"e");
    const char* c2_str=fragmapGet(&blocks[1],"c");

    if(!e1_str||!c1_str||!e2_str||!c2_str)
        return strdup("RSA mod error: malformed blocks");

    int ok1,ok2;

    long long e1=safe_strtoll(e1_str,&ok1);
    long long e2=safe_strtoll(e2_str,&ok2);

    if(!ok1||!ok2)
        return strdup("RSA mod error: invalid exponent");

    long long s,t;
    long long g=egcd_ll(e1,e2,&s,&t);

    if(g!=1 && g!=-1)
        return strdup("RSA mod error: exponents not coprime");

    if(g==-1){
        s=-s;
        t=-t;
    }

    BigInt N,C1,C2,term1,term2,M,tmp;

    biFromDec(&N,n_str);
    biFromDec(&C1,c1_str);
    biFromDec(&C2,c2_str);

    if(s>=0){
        BigInt eS;
        biFromLL(&eS,s);
        biPowMod(&term1,&C1,&eS,&N);
        biClear(&eS);
    }else{
        BigInt inv,eS;

        if(!biModInv(&inv,&C1,&N))
            return strdup("RSA mod error: C1 inverse fail");

        biFromLL(&eS,-s);
        biPowMod(&term1,&inv,&eS,&N);

        biClear(&inv);
        biClear(&eS);
    }

    if(t>=0){
        BigInt eT;
        biFromLL(&eT,t);
        biPowMod(&term2,&C2,&eT,&N);
        biClear(&eT);
    }else{
        BigInt inv,eT;

        if(!biModInv(&inv,&C2,&N))
            return strdup("RSA mod error: C2 inverse fail");

        biFromLL(&eT,-t);
        biPowMod(&term2,&inv,&eT,&N);

        biClear(&inv);
        biClear(&eT);
    }

    biMulMod(&tmp,&term1,&term2,&N);
    biCopy(&M,&tmp);

    char* plaintext=rsaDecodeDecimalToText(&M,alph);

    biClear(&N);
    biClear(&C1);
    biClear(&C2);
    biClear(&term1);
    biClear(&term2);
    biClear(&tmp);
    biClear(&M);

    if(!plaintext)
        return strdup("RSA mod error: decode failed");

    return plaintext;
}

/* ---------------- entry router ---------------- */

const char* rsaEntry(const char* alph,const char* encText,const char* frag)
{
    if(!frag || !*frag)
        return strdup("[RSA: missing fragment]");

    if(!encText)
        return strdup("[RSA: missing ciphertext]");

    if(strlen(encText)>MAX_INPUT_RSA)
        return strdup("[RSA: ciphertext too large]");

    char* copy=strdup(frag);
    if(!copy) return strdup("[OOM]");

    char* numbers[3]={0};
    int i=0;

    char* tok=strtok(copy,",");

    while(tok && i<3){
        numbers[i++]=tok;
        tok=strtok(NULL,",");
    }

    if(i<3){
        free(copy);
        return strdup("RSA error: fragment must contain n,e,d");
    }

    BigInt N,D,C,M;

    biFromDec(&N,numbers[0]);
    biFromDec(&D,numbers[2]);
    biFromDec(&C,encText);

    biPowMod(&M,&C,&D,&N);

    char* plaintext=rsaDecodeDecimalToText(&M,alph);

    biClear(&N);
    biClear(&D);
    biClear(&C);
    biClear(&M);

    free(copy);

    if(!plaintext)
        return strdup("RSA error: decode failed");

    return plaintext;
}