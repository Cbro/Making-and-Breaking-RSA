
/*
 * Cryptography lab 2
 * Making & Breaking RSA
 *
 * Description: This file contains RSA making and breaking related functions
 */

#include <stdlib.h>
#include <stdio.h>
#include <gmp.h>                /* needed to manipulate big-fat-ass int */
#include <time.h>
#include <math.h>
#include <glib.h>
#include "prime.h"
#include "rsa.h"


// Global Array and Hash 
// mpz_t *array;
GHashTable     *hash;



/*
 * This is the Square and Multiply functions.
 * This provide encryption & decryption of RSA
 */

void
square_and_mult(mpz_t x, mpz_t c, mpz_t n, mpz_t r)
{
    /*
     * mpz_t is the second name for big-fat-ass integer 
     */
    mpz_t           z;
    int             i;

    // z = (mpz_t *) malloc(sizeof(mpz_t));
    mpz_init_set_ui(z, 1);      /* init and set z to 1 */

    /*
     * mpz_sizeinbase return the size of the number in the specified base 
     */
    for (i = mpz_sizeinbase(c, 2) - 1; i >= 0; i--) {
        mpz_powm_ui(z, z, 2, n);        /* z = z^2 mod n */

        if (mpz_tstbit(c, i)) { /* mpz_tstbit return the value of the bit
                                 * i */
            mpz_mul(z, z, x);   /* z = z*x */
            mpz_mod(z, z, n);   /* z = z mod n */
        }
    }

    mpz_set(r, z);

    /*
     * Free Ressources !
     */
    mpz_clear(z);
}

/*
 * Multiplicative inverse
 * We assume that d is an allocated pointer to a mpz_t
 * return 1 if everything goes ok, 0 otherwise
 */
int
mul_inv(mpz_t d, mpz_t a, mpz_t b)
{
    mpz_t           a0,
                    b0,
                    t0,
                    t,
                    q,
                    r,
                    tmp;
    int             ret;

    ret = 1;

    mpz_init_set(a0, a);
    mpz_init_set(b0, b);
    mpz_init_set_ui(t0, 0);
    mpz_init_set_ui(t, 1);
    mpz_init(q);
    mpz_init(r);
    mpz_fdiv_qr(q, r, a0, b0);  /* calcul q and r at the same time */
    mpz_init(tmp);

    while (mpz_cmp_ui(r, 0) > 0) {
        mpz_mul(tmp, q, t);     /* tmp = qt */
        mpz_sub(t0, t0, tmp);   /* t0 = t0 - tmp */
        mpz_mod(tmp, t0, a);    /* tmp = t0 mod a */
        mpz_set(t0, t);
        mpz_set(t, tmp);
        mpz_set(a0, b0);
        mpz_set(b0, r);
        mpz_fdiv_qr(q, r, a0, b0);      /* q and r at the same time */
    }

    if (mpz_cmp_ui(b0, 1) != 0)
        ret = 0;                /* no inverse!! */
    else
        mpz_set(d, t);

    /*
     * Free Ressources
     */
    mpz_clear(a0);
    mpz_clear(b0);
    mpz_clear(t0);
    mpz_clear(t);
    mpz_clear(q);
    mpz_clear(r);
    mpz_clear(tmp);

    return ret;
}

/*
 * Keygen
 * Generate public and private key
 * We assume that e, t and n are allocated and initialized
 */
void
keygen(mpz_t e, mpz_t d, mpz_t n)
{
    mpz_t           p,
                    q,
                    phi,
                    tmp,
                    log2;
    gmp_randstate_t state;      /* random init stat */

    gmp_randinit_default(state);
    gmp_randseed_ui(state, time(NULL));

    mpz_init(p);
    mpz_init(q);

    /*
     * Generate p!=q
     */
    do {
        primegen(p);
        primegen(q);
    } while (!mpz_cmp(p, q));

    /*
     * n
     */
    mpz_mul(n, p, q);

    /*
     * phi(n)
     */
    mpz_init(phi);
    mpz_init(tmp);
    mpz_sub_ui(phi, p, 1);      /* phi = p-1 */
    mpz_sub_ui(tmp, q, 1);      /* tmp = q-1 */
    mpz_mul(phi, phi, tmp);     /* phi = phi*tmp */

    /*
     * Approximate log2n
     * To do so, we use bitcount+1.
     */
    mpz_init_set_ui(log2, mpz_sizeinbase(n, 2) + 1);

    /*
     * Choosing a random e
     */
    do {
        mpz_urandomm(e, state, phi);
        mpz_gcd(tmp, e, phi);
        /*
         * run until e > log2 and gcd(e. phi)=1
         */
    } while (mpz_cmp(e, log2) < 0 || mpz_cmp_ui(tmp, 1) != 0);

    /*
     * d := inv(e, phi(n))
     */
    if (mul_inv(d, phi, e) == 0) {
        printf
            ("Mayday mayday! Something went wrong! They are not inversible Oo Gonna explode !!");
        exit(-666);
    }

    /*
     * Free Ressources
     */
    mpz_clear(p);
    mpz_clear(q);
    mpz_clear(phi);
    mpz_clear(tmp);
    mpz_clear(log2);
    gmp_randclear(state);       /* random init stat */

}



void
build_table(unsigned long k, mpz_t e, mpz_t n, mpz_t * array)
{

    mpz_t           tmp,
                    local_p,
                    local_c;
    unsigned long   i = 0;
    unsigned long   array_size = (long) pow(2, k / 2.0);
    char           *key_str,
                   *value_str;

    /*
     * Create the hash
     */
    hash = g_hash_table_new(g_str_hash, g_str_equal);

    /*
     * Populate the hash and array
     */
    mpz_init(tmp);
    mpz_init(local_p);
    mpz_init(local_c);

    for (i = 1; i < array_size; i++) {
        mpz_set_ui(local_p, i); /* plain = i */
        square_and_mult(local_p, e, n, local_c);        /* c = i^e mod n */

        key_str = (char *) malloc(mpz_sizeinbase(local_c, 16) + 2);     // Allocate 
                                                                        // mem 
                                                                        // for 
                                                                        // key 
                                                                        // string
        key_str = mpz_get_str(NULL, 16, local_c);       /* c to HEX string 
                                                         */

        value_str = (char *) malloc(mpz_sizeinbase(local_p, 10) + 2);   // Allocate 
                                                                        // mem 
                                                                        // for 
                                                                        // value 
                                                                        // string
        value_str = mpz_get_str(NULL, 10, local_p);     /* p to string */
        g_hash_table_insert(hash, key_str, value_str);  /* add it to the
                                                         * hash */

        mpz_init(array[i]);     /* initialize the mpz in the array */
        mul_inv(array[i], n, local_c);  /* populate the array */
    }
    // Free Resources
    mpz_clear(local_p);
    mpz_clear(local_c);

}


/*
 * Break the rsa: the brutal way
 * c: cipher
 * e: e
 * n: n
 * k: the good k (size of the key ?)  
 * p: the plain version
 */
void
breakit(mpz_t c, mpz_t e, mpz_t n, unsigned long k, mpz_t p, mpz_t * array)
{
    mpz_t           tmp;
    unsigned long   array_size = (long) pow(2, k / 2.0);

    unsigned long   i,
                    j;
    char           *key_str,
                   *val;
    mpz_init(tmp);
    /*
     * Crack it baby!
     */
    for (i = 1; i < array_size; i++) {

        mpz_mul(tmp, c, array[i]);      /* tmp = c * inv(i^e mod n, n) */
        mpz_mod(tmp, tmp, n);   /* tmp = c * inv(i^e mod n, n) mod n */

        key_str = (char *) malloc(mpz_sizeinbase(tmp, 16) + 2); // Allocate 
                                                                // mem for 
                                                                // key
                                                                // string
        mpz_get_str(key_str, 16, tmp);  /* c to HEX string */
        /*
         * Hash search
         */
        val = g_hash_table_lookup(hash, key_str);
        if (val != NULL) {
            j = atoi(val);
            mpz_set_ui(tmp, 1); /* tmp = 1 */
            mpz_mul_ui(tmp, tmp, i);    /* tmp = i */
            mpz_mul_ui(tmp, tmp, j);    /* tmp = i*j */
            mpz_mod(tmp, tmp, n);       /* tmp = i*j mod n */
            mpz_set(p, tmp);    /* set the plain text */
            break;
        }
    }

    /*
     * Free Ressources
     */
    mpz_clear(tmp);
}
