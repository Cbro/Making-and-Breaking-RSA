/*
 * Cryptography lab 2
 * Making & Breaking RSA
 *
 * Description: This file contains function to test and generate prime number
 */

#include <stdlib.h>
#include <stdio.h>
#include <gmp.h>                /* needed to manipulate big-fat-ass int */
#include <time.h>
#include "prime.h"

/*
 * Global variable time
 */

volatile int    PRIME_LENGTH = 16;      /* lenght of the generated prime */
volatile int    ACCURACY = 50;  /* number of check for the generated prime 
                                 */

/*
 * isprime : is this number prime ?
 * this use the Miller-Rabin method. The algorithm can be found at Wikipedia
 * return 1 (yes) and 0 (no)
 */
int
isprime(mpz_t p)
{
    gmp_randstate_t st;         /* random init stat */
    mpz_t           a,
                    d,
                    tmp,
                    x;
    int             i,
                    ret,
                    j;
    unsigned long   s;

    ret = 1;

    /*
     * ensure that p is odd and greater than 3 
     */
    if (mpz_cmp_ui(p, 3) <= 0 || !mpz_tstbit(p, 0))
        return 0;

    /*
     * put p in the 2^s.d form
     */
    mpz_init(d);
    mpz_sub_ui(d, p, 1);        /* d = p-1 */
    s = 0;

    do {
        s++;
        mpz_divexact_ui(d, d, 2);
    } while (mpz_divisible_ui_p(d, 2));
    /*
     * now we have p as 2^s.d
     */

    gmp_randinit_default(st);
    gmp_randseed_ui(st, time(NULL));
    mpz_init(a);
    mpz_init(x);
    mpz_init(tmp);
    mpz_sub_ui(tmp, p, 1);      /* tmp = p - 1 */

    for (i = 0; i < ACCURACY; i++) {
        /*
         * generate a as 2 <= a <= n-2 
         */
        do {
            mpz_urandomm(a, st, tmp);   /* a will be between 0 and * tmp-1 
                                         * inclusive */
        } while (mpz_cmp_ui(a, 2) < 0);

        mpz_powm(x, a, d, p);   /* do x = a^d mod p */

        /*
         * if x == 1 or x == p-1 
         */
        if (!mpz_cmp_ui(x, 1) || !mpz_cmp(x, tmp))
            continue;

        for (j = 1; j < s; j++) {
            mpz_powm_ui(x, x, 2, p);    /* do x = x^2 mod p */
            if (!mpz_cmp_ui(x, 1)
                || !mpz_cmp(x, tmp))    /* x == 1 */
                break;
        }

        if (mpz_cmp(x, tmp) || !mpz_cmp_ui(x, 1)) {     /* x != p-1 */
            ret = 0;
            break;
        }
    }

    /*
     * Free Ressources
     */
    gmp_randclear(st);
    mpz_clear(a);
    mpz_clear(d);
    mpz_clear(tmp);

    return ret;
}

/*
 * primegen : generate a prime number
 * assume that p is an allocated pointer, and a initialized
 * mpz_t
 */

void
primegen(mpz_t p)
{
    gmp_randstate_t state;      /* random init stat */
    unsigned long   i;

    i = 0;
    gmp_randinit_default(state);
    gmp_randseed_ui(state, time(NULL));

    do {
        mpz_urandomb(p, state, PRIME_LENGTH);
    } while (!isprime(p));

    /*
     * Free Ressources
     */
    gmp_randclear(state);
}

/*
 * Set the size of the prime
 */
void
set_prime_size(int s)
{
    PRIME_LENGTH = s;           /* lenght of the generated prime */
}
