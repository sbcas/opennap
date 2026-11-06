/* Focused tests for malformed password records and decompression limits. */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <zlib.h>
#include "opennap.h"

time_t Current_Time;

int main (void)
{
    char *record, malformed[256];
    unsigned char *input, *compressed;
    uLongf compressed_len;
    BUFFER b;
    z_stream stream;

    Current_Time = time (0);
    init_random ();
    record = generate_pass ("password");
    assert (record && valid_pass_record (record));
    assert (check_pass (record, "password") == 0);
    assert (check_pass (record, "wrong") != 0);
    assert (!valid_pass_record ("1,"));
    assert (check_pass ("1,", "password") != 0);
    memset (malformed, 'A', sizeof (malformed));
    malformed[sizeof (malformed) - 1] = 0;
    memcpy (malformed, record, 11);
    assert (check_pass (malformed, "password") != 0);
    memcpy (malformed, record, 34);
    malformed[12] = (char) 0xff;
    assert (check_pass (malformed, "password") != 0);
    free (record);

    input = calloc (1, 2 * 1024 * 1024);
    compressed_len = compressBound (2 * 1024 * 1024);
    compressed = malloc (compressed_len);
    assert (input && compressed);
    assert (compress2 (compressed, &compressed_len, input,
                       2 * 1024 * 1024, 9) == Z_OK);
    memset (&stream, 0, sizeof (stream));
    memset (&b, 0, sizeof (b));
    b.data = malloc (5);
    b.datamax = 4;
    assert (b.data && inflateInit (&stream) == Z_OK);
    assert (buffer_decompress (&b, &stream, (char *) compressed,
                               (int) compressed_len) == -1);
    assert (b.datamax <= 1024 * 1024);
    inflateEnd (&stream);
    free (b.data);
    free (compressed);
    free (input);
    puts ("security tests passed");
    return 0;
}
