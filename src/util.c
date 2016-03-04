/*
 *  Off-the-Record Messaging library
 *  Copyright (C) 2004-2016  Ian Goldberg, David Goulet, Rob Smits,
 *                           Chris Alexander, Willy Lew, Lisa Du,
 *                           Nikita Borisov, Isis Lovecruft
 *                           <otr@cypherpunks.ca>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of version 2.1 of the GNU Lesser General
 *  Public License as published by the Free Software Foundation.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

/* system headers */
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>

/* libgcrypt headers */
#include <gcrypt.h>

/* libotr headers */
#include "sm.h"
#include "serial.h"

/* Get a buffer of `nbytes` of randomness.
 *
 * If the `secure` flag is 1, then `gcry_random_bytes_secure` will be called,
 * otherwise if 0 then `gcry_random_bytes_secure` will be called.
 *
 * This function can output at most 32-bytes, due to passing the RNG output
 * through SHA2-256 before returning.
 *
 * WARNING: The caller is responsible for freeing the returned buffer.
 */
void * otrl_random_bytes(size_t nbytes, const int secure)
{
     void *rng_output;
     void *hash_output;
     void *ret;

     if (nbytes > 32)
         return NULL;

     rng_output = secure
         ? gcry_random_bytes_secure(nbytes, GCRY_STRONG_RANDOM)
         : gcry_random_bytes(nbytes, GCRY_STRONG_RANDOM);

     hash_output = malloc(32); /* Allocate 32 bytes for the SHA2-256 output. */
     memset(hash_output, 0, 32);
     gcry_md_hash_buffer(GCRY_MD_SHA256, hash_output, rng_output, nbytes);

     if (nbytes < 32) {        /* Truncate the SHA2-256 output to nbytes. */
         ret = realloc(hash_output, nbytes);
         if (! ret)
             return NULL;
     } else {
         ret = hash_output;
     }

     return ret;
}

/* Randomize the contents of the buffer of the given length.  The randomness
 * retrieved from the RNG is hashed with SHA2-256 to protect against
 * accidental disclosure of the state of the RNG.
 *
 * This function can output at most 32 bytes, due to passing the RNG output
 * through SHA2-256 before returning.
 *
 * Returns: a gcry_error_t, with value GPG_ERR_INV_VALUE if the length is
 * greater than 32, otherwise it has value GPG_ERR_NO_ERROR if no error
 * occured.
 */
gcry_error_t otrl_randomize(void *buffer, size_t length)
{
    void *hash_output;
    gcry_error_t err = gcry_error(GPG_ERR_NO_ERROR);

    if (length > 32)
        err = gcry_error(GPG_ERR_INV_VALUE);
        return err;

    hash_output = malloc(32); /* Allocate 32 bytes for the SHA2-256 output. */
    memset(hash_output, 0, 32);

    gcry_randomize(buffer, length, GCRY_STRONG_RANDOM);
    gcry_md_hash_buffer(GCRY_MD_SHA256, hash_output, buffer, length);

    memcpy(buffer, hash_output, length);
    free(hash_output);        /* Free the buffer for the hash output. */

    return err;
}
