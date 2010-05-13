
/*
 * Cryptography lab 2
 * Making & Breaking RSA
 */

#include <stdlib.h>
#include <stdio.h>
#include <gmp.h>                /* needed to manipulate big-fat-ass int */
#include <time.h>
#include <unistd.h>
#include <string.h>
#include <math.h>

#include "prime.h"
#include "rsa.h"

/*
 * Define
 */

enum { ATTACK, HELP, TEST };

/*
 * Functions declarations
 */

void            all_test(void);
void            ed_test(void);
void            prime_test(void);
void            key_test(void);
void            breakit_test(void);
void            attack(char *file, unsigned long k);

/*
 * Encryptien/Decryption test
 */
void
ed_test(void)
{
    mpz_t           n,
                    a,
                    b,
                    x,
                    p,
                    c;

    /*
     * little test of Square & Multiply functions
     * Using exemple in the book page 177 (Example 5.5)
     * n = 11413
     * b = 3533
     * plaintext = 9726
     * cypher = 5761
     */

    printf("-- Testing the encryption/decryption\n");

    mpz_init(x);
    mpz_init_set_ui(n, 11413);
    mpz_init_set_ui(b, 3533);
    mpz_init_set_ui(a, 6597);
    mpz_init_set_ui(p, 9726);
    mpz_init_set_ui(c, 5761);

    printf("n = ");
    mpz_out_str(stdout, 10, n);
    printf("\nb = ");
    mpz_out_str(stdout, 10, b);
    printf("\nplain = ");
    mpz_out_str(stdout, 10, p);
    printf("\nexcpected cypher = ");
    mpz_out_str(stdout, 10, c);
    printf("\n");

    square_and_mult(p, b, n, x);        /* x contains the calculted cypher 
                                         */

    printf("found cypher = ");
    mpz_out_str(stdout, 10, x);
    printf("\n");

    square_and_mult(x, a, n, x);        /* x contains the calculated plain 
                                         */

    printf("back to = ");
    mpz_out_str(stdout, 10, x);
    printf("\n");

    if (mpz_cmp(x, p) == 0)     /* return 0 if equal */
        printf("zOMG !! It's working!! Oo\n");
    else
        printf("fail n00b!!\n");

    /*
     * Free Ressources !
     */
    mpz_clear(n);
    mpz_clear(a);
    mpz_clear(b);
    mpz_clear(x);
    mpz_clear(p);
    mpz_clear(c);
}

/*
 * Prime generator test
 */
void
prime_test(void)
{
    mpz_t           p;

    printf("\n-- Prime test\n");

    mpz_init_set_ui(p, 0);

    primegen(p);
    printf("This is a prime number: ");
    mpz_out_str(stdout, 10, p);
    printf("\nYep really! Test it with: openssl prime <number>");

    /*
     * Free Ressources
     */
    mpz_clear(p);
}

/*
 * Keygen, encryption and decryption with generated key
 */
void
key_test(void)
{
    mpz_t           e,
                    d,
                    n,
                    x,
                    c;

    printf("\n-- Keygen test\n");
    mpz_init(e);
    mpz_init(d);
    mpz_init(n);
    mpz_init(c);

    keygen(e, d, n);

    printf("--Generated key:\nPublic: (");
    mpz_out_str(stdout, 10, e);
    printf(", ");
    mpz_out_str(stdout, 10, n);
    printf(")\nPrivate: (");
    mpz_out_str(stdout, 10, d);
    printf(", ");
    mpz_out_str(stdout, 10, n);
    printf(")\n");

    printf("With this key i'll encrypt: ");
    mpz_init_set_ui(x, 111000);
    mpz_out_str(stdout, 10, x);

    square_and_mult(x, e, n, c);

    printf("\ngot: ");
    mpz_out_str(stdout, 10, c);
    printf("\nNow we try to decrypt it: ");

    square_and_mult(c, d, n, x);

    printf("\ngot: ");
    mpz_out_str(stdout, 10, x);
    printf("\n");

    /*
     * Free Ressources !
     */
    mpz_clear(e);
    mpz_clear(d);
    mpz_clear(n);
    mpz_clear(x);
    mpz_clear(c);
}

/*
 * Break test
 */
void
breakit_test(void)
{
    mpz_t           n,
                    e,
                    x,
                    c,
                    d;

    printf("\n-- Try to break\n");

    printf("1. Key generation :");

    mpz_init(x);
    mpz_init(n);
    mpz_init(e);
    mpz_init(d);
    mpz_init(c);

    // set_prime_size(8);
    keygen(e, d, n);

    printf("\nPublic: (");
    mpz_out_str(stdout, 10, e);
    printf(", ");
    mpz_out_str(stdout, 10, n);
    printf(")\nPrivate: (");
    mpz_out_str(stdout, 10, d);
    printf(", ");
    mpz_out_str(stdout, 10, n);
    printf(")\n");

    printf("2. With this key i'll encrypt: ");
    mpz_init_set_ui(x, 111000);
    mpz_out_str(stdout, 10, x);

    square_and_mult(x, e, n, c);

    printf("\ngot: ");
    mpz_out_str(stdout, 10, c);

    printf("\n3. Try to break it\n");
    mpz_set_ui(x, 0);
    // breakit(c, e, n, 32, x);

    printf("found plain = ");
    mpz_out_str(stdout, 10, x);
    printf("\n");

    if (!mpz_cmp_ui(x, 111000))
        printf("zOMG !! It's working!! Oo\n");
    else
        printf("fail n00b!!\n");

    /*
     * Free Ressources
     */
    mpz_clear(n);
    mpz_clear(e);
    mpz_clear(x);
    mpz_clear(c);
    mpz_clear(d);
}


/*
 * all the test
 */
void
all_test(void)
{

    ed_test();                  /* encryption/decryption test */
    prime_test();               /* prime generator */
    key_test();                 /* key generator */
    breakit_test();             /* break test */
}

/*
 * Attack RSA
 * To be use with the lab file
 */
void
attack(char *f, unsigned long k)
{
    FILE           *file;
    char            ckey[256],
                    cn[256],
                    cc[256],
                    cp[3];
    mpz_t           key,
                    n,
                    c,
                    p;
    unsigned long   ip;
    clock_t         timer;

    file = fopen(f, "r");

    /*
     * read the key
     */
    fgets(ckey, 256, file);
    mpz_init_set_str(key, ckey, 10);
    printf("Key: ");
    mpz_out_str(stdout, 10, key);
    printf("\n");

    /*
     * read n
     */
    fgets(cn, 256, file);
    mpz_init_set_str(n, cn, 10);
    printf("Modulus: ");
    mpz_out_str(stdout, 10, n);
    printf("\n");

    /*
     * Break it baby!
     */
    mpz_init(c);
    mpz_init(p);

    /*
     * Allocate the array for the result
     */
    unsigned long   array_size = (unsigned long) pow(2, k / 2.0);
    mpz_t          *inv_array =
        (mpz_t *) malloc(array_size * sizeof(mpz_t));

    timer = clock();

    /*
     * Build the table once upfront 
     */
    build_table(k, key, n, inv_array);

    while (fgets(cc, 256, file) != NULL) {
        mpz_set_str(c, cc, 10);
        /*
         * Break the Cipher 
         */
        breakit(c, key, n, k, p, inv_array);

        ip = mpz_get_ui(p);

        cp[1] = (char) (ip & 0x0ff);
        cp[0] = (char) (ip >> 8 & 0x0ff);
        cp[2] = '\0';

        printf(cp);
    }

    printf("\nTime: %lf\n", (double) (clock() - timer) / CLOCKS_PER_SEC);
    fclose(file);

    /*
     * Free Ressources
     */
    free(inv_array);
    mpz_clear(key);
    mpz_clear(n);
    mpz_clear(c);
    mpz_clear(p);

}

/*
 * Main
 */

int
main(int argc, char **argv)
{
    int             k,
                    flag,
                    c;
    char           *file;

    k = 32;
    flag = HELP;
    file = NULL;

    if (argc == 1) {
        printf("Please provide option or -h");
        return 0;
    }

    while ((c = getopt(argc, argv, "a:k:ht")) != -1)
        switch (c) {
        case 'h':
            printf("Not yet implemented ^^\n");
            exit(0);
        case 't':
            flag = TEST;
            break;
        case 'k':
            k = atoi(optarg);
            break;
        case 'a':
            flag = ATTACK;
            file = optarg;
            break;
        }


    switch (flag) {
    case TEST:
        all_test();
        break;

    case ATTACK:
        attack(file, k);
        break;
    }

    return 0;
}
