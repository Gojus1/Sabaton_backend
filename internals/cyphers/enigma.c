#include "enigma.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_ALPH 256
#define MAX_TEXT 4096
#define MAX_BRUTE 4096

/* Build fast alphabet index table */
static void build_index(const char* alph, int* table)
{
    for (int i = 0; i < 256; i++)
        table[i] = -1;

    for (int i = 0; alph[i]; i++)
        table[(unsigned char)alph[i]] = i;
}

/* Simple Enigma */
static char* runSimpleEnigma(
    const char* text,
    const char* alph,
    const int* rotor1,
    const int* rotor2,
    int pos1,
    int pos2,
    int decrypt)
{
    size_t N = strlen(alph);
    size_t len = strlen(text);

    if (len > MAX_TEXT)
        return strdup("[text too long]");

    char* result = malloc(len + 1);
    if (!result)
        return strdup("[memory error]");

    int index_table[256];
    build_index(alph, index_table);

    int start1 = pos1;

    for (size_t k = 0; k < len; k++)
    {
        char c = text[k];
        int index = index_table[(unsigned char)c];

        if (index < 0)
        {
            result[k] = c;
            continue;
        }

        int step1, step2;

        if (!decrypt)
        {
            step1 = (rotor1[(index + pos1) % N] - pos1 + N) % N;
            step2 = (rotor2[(step1 + pos2) % N] - pos2 + N) % N;
        }
        else
        {
            step1 = (rotor2[(index + pos2) % N] - pos2 + N) % N;
            step2 = (rotor1[(step1 + pos1) % N] - pos1 + N) % N;
        }

        result[k] = alph[step2];

        pos1 = (pos1 + 1) % N;
        if (pos1 == start1)
            pos2 = (pos2 + 1) % N;
    }

    result[len] = '\0';
    return result;
}

/* Reflector Enigma */
static char* runReflectorEnigma(
    const char* text,
    const char* alph,
    const int* rotor1,
    const int* rotor2,
    int pos1,
    int pos2,
    const int* reflector)
{
    size_t N = strlen(alph);
    size_t len = strlen(text);

    if (len > MAX_TEXT)
        return strdup("[text too long]");

    int inv1[MAX_ALPH], inv2[MAX_ALPH];
    invertVector(rotor1, inv1, (int)N);
    invertVector(rotor2, inv2, (int)N);

    int index_table[256];
    build_index(alph, index_table);

    char* result = malloc(len + 1);
    if (!result)
        return strdup("[memory error]");

    int start1 = pos1;

    for (size_t k = 0; k < len; k++)
    {
        char c = text[k];
        int index = index_table[(unsigned char)c];

        if (index < 0)
        {
            result[k] = c;
            continue;
        }

        int step1 = (rotor1[(index + pos1) % N] - pos1 + N) % N;
        int step2 = (rotor2[(step1 + pos2) % N] - pos2 + N) % N;
        int step3 = reflector[step2];
        int step4 = (inv2[(step3 + pos2) % N] - pos2 + N) % N;
        int step5 = (inv1[(step4 + pos1) % N] - pos1 + N) % N;

        result[k] = alph[step5];

        pos1 = (pos1 + 1) % N;
        if (pos1 == start1)
            pos2 = (pos2 + 1) % N;
    }

    result[len] = '\0';
    return result;
}

const char* enigmaEntry(const char* alph, const char* encText, const char* frag)
{
    if (!alph || !encText)
        return strdup("[invalid input]");

    size_t N = strlen(alph);

    if (N == 0 || N > MAX_ALPH)
        return strdup("[invalid alphabet]");

    if (strlen(encText) > MAX_TEXT)
        return strdup("[cipher too large]");

    int rotor1[MAX_ALPH], rotor2[MAX_ALPH], reflector[MAX_ALPH];
    int r1Count = 0, r2Count = 0, refCount = 0;

    int key[2] = { -1, -1 };
    char* plainFrag = NULL;

    if (frag)
    {
        char* copy = strdup(frag);
        char* part = strtok(copy, ",");

        while (part)
        {
            if (strncmp(part,"R1:",3)==0)
                parseCSV(part+3,rotor1,&r1Count);

            else if (strncmp(part,"R2:",3)==0)
                parseCSV(part+3,rotor2,&r2Count);

            else if (strncmp(part,"REF:",4)==0)
                parseCSV(part+4,reflector,&refCount);

            else if (strncmp(part,"KEY:",4)==0)
            {
                int tmp[8]={0},count=0;
                parseCSV(part+4,tmp,&count);
                if(count>0) key[0]=tmp[0];
                if(count>1) key[1]=tmp[1];
            }

            else if (strncmp(part,"PLAIN:",6)==0)
                plainFrag=strdup(part+6);

            part=strtok(NULL,",");
        }

        free(copy);
    }

    if (r1Count != N || r2Count != N)
        return strdup("[invalid rotor size]");

    if (refCount && refCount != N)
        return strdup("[invalid reflector]");

    int inv1[MAX_ALPH], inv2[MAX_ALPH];
    invertVector(rotor1,inv1,(int)N);
    invertVector(rotor2,inv2,(int)N);

    char* output=NULL;

    int bruteCount=0;

    int max1=(key[0]==-1)?(int)N:1;
    int max2=(key[1]==-1)?(int)N:1;

    for(int p1=0;p1<max1;p1++)
    for(int p2=0;p2<max2;p2++)
    {
        if(++bruteCount>MAX_BRUTE)
            break;

        int pos1=(key[0]==-1)?p1:key[0];
        int pos2=(key[1]==-1)?p2:key[1];

        char* cand=(refCount>0)
            ? runReflectorEnigma(encText,alph,rotor1,rotor2,pos1,pos2,reflector)
            : runSimpleEnigma(encText,alph,inv1,inv2,pos1,pos2,1);

        int ok=1;

        if(plainFrag)
            ok=(strstr(cand,plainFrag)!=NULL);

        if(ok)
        {
            output=strdup(cand);
            free(cand);
            break;
        }

        free(cand);
    }

    if(!output)
        output=strdup("[no match]");

    if(plainFrag)
        free(plainFrag);

    return output;
}