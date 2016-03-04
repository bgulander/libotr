/*
 * Copyright (C) 2016 - Isis Lovecruft <isis@patternsinthevoid.net>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License, version 2 only, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <util.h>
#include <gcrypt.h>
#include <pthread.h>

#include <tap/tap.h>
#include <utils.h>
#include <proto.h>

GCRY_THREAD_OPTION_PTHREAD_IMPL;

#define NUM_TESTS 5

static void test_util_random_bytes(void)
{
    void *buffer;
    size_t nbytes = 32;

    buffer = otrl_random_bytes(nbytes, 0);
    ok(buffer && !utils_is_zeroed(buffer, nbytes),
       "Got 32 bytes of randomness");
    free(buffer);
}

static void test_util_random_bytes_secure(void)
{
    void *buffer;
    size_t nbytes = 32;

    buffer = otrl_random_bytes(nbytes, 1);
    ok(!utils_is_zeroed(buffer, nbytes),
       "Got 32 bytes of randomness");
    free(buffer);
}

static void test_util_random_bytes_greater_than_32(void)
{
    void *buffer;
    size_t nbytes = 40;

    buffer = otrl_random_bytes(nbytes, 0);
    ok(!buffer, "Got NULL because we asked for too many bytes");
    free(buffer);
}

static void test_util_random_bytes_less_than_32(void)
{
    void *buffer;
    size_t nbytes = 16;

    buffer = otrl_random_bytes(nbytes, 0);
    ok(!utils_is_zeroed(buffer, nbytes),
       "Got 16 bytes of randomness");
    free(buffer);
}

static void test_util_randomize(void)
{
    gcry_error_t err;
    size_t length;
    void *buffer;

    length = 32;
    buffer = malloc(length);

    err = otrl_randomize(buffer, length);
    ok(err == 0 && !utils_is_zeroed(buffer, length),
       "Randomized 32 bytes of memory");
    free(buffer);
}

int main(int argc, char **argv)
{
    /* Libtap call for the number of tests planned. */
	plan_tests(NUM_TESTS);

	gcry_control(GCRYCTL_SET_THREAD_CBS, &gcry_threads_pthread);
	OTRL_INIT;

	/* Initialize libotr. */
	otrl_dh_init();

    test_util_random_bytes();
    test_util_random_bytes_secure();
    test_util_random_bytes_greater_than_32();
    test_util_random_bytes_less_than_32();
    test_util_randomize();

	return 0;
}
