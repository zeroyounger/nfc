/*  test.c

    This program is free software; you can redistribute it and/or
    modify it under the terms of the GNU General Public License
    as published by the Free Software Foundation; either version 2
    of the License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, US$

    Copyright (C) 2008-2008 bla <blapost@gmail.com>
*/


#include "crypto1.h"
#include "crapto1.h"

#include <stdio.h>

struct TestCase{
	/* shared secret */
	uint64_t key;
	/* sent by tag */
	uint32_t uid, nt; 
	/* sent by reader */
	uint32_t nr_enc, nr, ar;
	/* sent by tag */
	uint32_t at;
	uint32_t data[5];
} tc[] = {
		{0xffffffffffffULL,
		 0x7BED1AFD, 0x01020304,
		 0x12345678, 0x5BF4F60E, 0x8D3A9A9C,
		 0x7208E6C6,
		 {0xF0293188, 0x96188BA7, 0x8743C386, 0x4BAFEEF2, 0x9F5B3C53}},
		{0xa5a4a3a2a1a0ULL,
		 0x8CBA5DD3, 0x0DF547C9,
		 0x851E2949, 0x55414992, 0xBF445BEB,
		 0xA586F437, {0,0,0,0,0}},
	 };


#define NUMTESTS (sizeof(tc) / sizeof(struct TestCase))
int main (void)
{
	struct Crypto1State state, revstate;
	uint32_t k, tresp, rresp, rchal;
	uint32_t ks0, ks1, ks2, ks3;
	uint64_t lfsr;

	for (k = 0; k < NUMTESTS; k++)
	{
		printf("Test case %d:\n", k);
		//on the tag
		printf("on the tag\n");
		crypto1_init(&state, tc[k].key);
		crypto1_word(&state, tc[k].uid ^ tc[k].nt, 0); // ks0
		ks1 = crypto1_word(&state, tc[k].nr_enc, 1);
		rresp = prng_successor(tc[k].nt, 64); // suc64
		ks2 = crypto1_word (&state, 0, 0); // ks2
		printf("ks2:%08x\n", ks2);
		rresp ^= ks2;

		if(rresp == tc[k].ar)
			printf("TAG> Reader is authentic.\n");
		else
			printf("TAG> Reader is NOT authentic.\n");


		//in the reader
		printf("in the reader\n");
		crypto1_init(&state, tc[k].key);
		crypto1_word(&state, tc[k].uid ^ tc[k].nt, 0);
		rchal = crypto1_word(&state, tc[k].nr, 0); //ks1
		printf("ks1:%08x\n", rchal);
		rresp = prng_successor(tc[k].nt, 64); // suc64
		ks2 = crypto1_word (&state, 0, 0); // ks2
		printf("ks2:%08x\n", ks2);
		rresp ^= ks2;
		tresp = prng_successor(tc[k].nt, 96); // suc96
		ks3 = crypto1_word (&state, 0, 0); // ks3
		printf("ks3:%08x\n", ks3);
		tresp ^= ks3;
		if(tresp == tc[k].at)
			printf("Reader> Tag is authentic.\n");
		else
			printf("Reader> Tag is NOT authentic.\n");


		//sniffing and extracting ks2 and ks3
		crypto1_init(&state, tc[k].key);
		crypto1_word(&state, tc[k].uid ^ tc[k].nt, 0);
		ks1 = crypto1_word(&state, tc[k].nr_enc, 1);
		ks2 = crypto1_word(&state, 0, 0);
		ks3 = crypto1_word(&state, 0, 0);
		printf("ks2:%08x\n", ks2);
		printf("ks3:%08x\n", ks3);


		//reverse, and compute the current lsfr state from keystream
		lfsr_recovery(&revstate, ks2, ks3);
		if(crypto1_word(&revstate, 0,0) == crypto1_word(&state, 0, 0))
			printf("Successfully reversed keystream to lfsr\n");
		else
			printf("Failed to reverse keystream to lfsr\n");

		//rollback lfsr to get key

		lfsr_rollback(&revstate, 0, 0);
		lfsr_rollback(&revstate, 0, 0);
		lfsr_rollback(&revstate, 0, 0);
		lfsr_rollback(&revstate, tc[k].nr_enc, 1);
		lfsr_rollback(&revstate, tc[k].uid ^ tc[k].nt, 0);
		
		crypto1_get_lfsr(&revstate, &lfsr);

		if(lfsr ==  tc[k].key)
			printf("Managed to recover the SECRET KEY!\n\n");
		else
			printf("FAILED to recover the SECRET KEY!\n\n");

	}


	return 0;
}
