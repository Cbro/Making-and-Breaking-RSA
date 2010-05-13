/*
 * Cryptography lab 2
 * Making & Breaking RSA
 *
 * Description: This file contains RSA making and breaking related functions
 */

void            square_and_mult(mpz_t x, mpz_t c, mpz_t n, mpz_t r);
int             mul_inv(mpz_t d, mpz_t a, mpz_t b);
void            keygen(mpz_t e, mpz_t d, mpz_t n);
void            breakit(mpz_t c, mpz_t e, mpz_t n, unsigned long k,
                        mpz_t p, mpz_t * array);
void            build_table(unsigned long k, mpz_t key, mpz_t n,
                            mpz_t * array);
