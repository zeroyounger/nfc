/*  crapto1.c

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


#include "crapto1.h"
#include "crypto1.h"
#include <stdlib.h>

#define BIT(x, n) ((x) >> (n) & 1)

#define LF_POLY_ODD (0x29CE5C)
#define LF_POLY_EVEN (0x870804)
/*
 * parity 32位值的奇偶校验
 * Calculate the parity of a 32 bit value
 *
 * It is used to evaluate polynomials over F2
 */
static uint32_t parity(uint32_t x)
{
	x ^= x >> 16;
	x ^= x >> 8;
	x ^= x >> 4;			
			
	return BIT(0x6996, x & 0xf);
}

/*
 * filter 滤波函数
 * Implementation of Crypto1 filter function
 *
 * Look up the corresponding output bit for the 20 input bits in x
 * uses the 20 lsb of x, in reverse order BIT(x, 0) = BIT(lfsr, 47),
 * BIT(x, 1) = BIT(lfsr, 45), ..., BIT(x, 20) = BIT(lfsr, 9)
 */
static int
filter(uint32_t x)
{
	uint32_t f;

	f =  0x0D938 >> (x >> 0x10 & 0xf) &  1;
	f |= 0x1e458 >> (x >> 0x0C & 0xf) &  2;
	f |= 0x3c8b0 >> (x >> 0x08 & 0xf) &  4;
	f |= 0x6c9c0 >> (x >> 0x04 & 0xf) &  8;
	f |= 0xf22c0 >> (x >> 0x00 & 0xf) & 16;
	return BIT(0xEC57E80A, f);
}

/*
 * extend_table
 * using a bit of the keystream extend the table of possible lfsr states
 */
static int
extend_table(uint64_t *table, uint64_t len, int bit)
{
	uint32_t i;

	for(i = 0; i < len; i++)
	{
		table[i] <<= 1;
		if(filter(table[i]) == bit)
		{
			if(filter(table[i] | 1) == bit)
			{
				table[len++] = table[++i];
				table[i] = table[i - 1] | 1;
			}
		} else if(filter(table[i] | 1) == bit)
			table[i] |= 1;
		else
			table[i--] = table[--len];
	}

	return len;
}
/*
 * quicksort
 * in place quicksort of table, keep shadow table in sync.
 */
static void
quicksort(uint64_t *table, uint64_t *shadow, uint32_t start, uint32_t stop)
{
	int it = start;
	int rit = stop;
	uint64_t pivot, swap;

	if(rit <= it)
		return;

	pivot = table[it++];
	while(it <= rit)
	{
		if(table[it] < pivot)
			++it;
		else if (table[rit] >= pivot)
			--rit;
		else {
			swap = table[it];
			table[it] = table[rit];
			table[rit] = swap;
			swap = shadow[it];
			shadow[it] = shadow[rit];
			shadow[rit] = swap;
		}
	}

	swap = table[start];
	table[start] = table[rit];
	table[rit] = swap;
	swap = shadow[start];
	shadow[start] = shadow[rit];
	shadow[rit] = swap;

	quicksort(table, shadow, start, rit - 1);
	quicksort(table, shadow, rit + 1, stop);
}


/*
 * lfsr_recovery
 * recover the state of the lfsr given a part of the keystream
 */
void
lfsr_recovery(struct Crypto1State * s, uint32_t ks2, uint32_t ks3)
{	
	uint32_t odd_ks = 0, even_ks = 0;
	uint64_t *odd_table = 0, *even_table = 0;
	uint64_t *omatch_table = 0, *ematch_table = 0;
	uint32_t otab_len = 0, etab_len = 0;
	uint32_t p, odd_res, even_res;
	uint64_t lfsr = 0;
	int i, j;


	odd_table = malloc(8 << 21);
	even_table = malloc(8 << 21);
	if(!odd_table || !even_table)
		goto out;



	//split ks2,ks3 into a odd and even bits
	for(i = 0; i < 32; i += 2)
	{
 		even_ks |= BIT(ks2, i ^ 24) << (i/2);
 		even_ks |= BIT(ks3, i ^ 24) << (16 + i/2);

		odd_ks |= BIT(ks2, (i + 1) ^ 24) << (i/2);
		odd_ks |= BIT(ks3, (i + 1) ^ 24) << (16 + i/2);
	}


	//seed the tables using the first 2 bits of keystream
	for(i = 0; i < (1 << 20); i++)
	{
		if(filter(i) == BIT(even_ks, 0))
			even_table[etab_len++] = i;

		if(filter(i) == BIT(odd_ks, 0))
			odd_table[otab_len++] = i;
	}

	for(i = 1; i < 32; i++)
	{
		etab_len = extend_table(even_table, etab_len, BIT(even_ks, i));
		otab_len = extend_table(odd_table, otab_len, BIT(odd_ks, i));
	}


	ematch_table = malloc(etab_len << 3);
	omatch_table = malloc(otab_len << 3);
	if(!ematch_table || !omatch_table)
		goto out;

	//compute the lsfr contributions of the even bits
	for(i = 0; i < etab_len; i++)
	{
		ematch_table[i] = 0;
		for(j = 0; j < (32 - 5); j++)
		{
			ematch_table[i] <<= 1;
			p = even_table[i] >> j & (LF_POLY_EVEN * 2 + 1);
			ematch_table[i] |= parity(p);

			ematch_table[i] <<= 1;
			p = even_table[i] >> j & LF_POLY_ODD;
			ematch_table[i] |= parity(p);
		}
	}
	
	//compute the lsfr contributions of the odd bits
	for(i = 0; i < otab_len; i++)
	{
		omatch_table[i] = 0;
		for(j = 0; j < (32 - 5); j++)
		{
			omatch_table[i] <<= 1;
			p = odd_table[i] >> j & LF_POLY_ODD * 2;
			omatch_table[i] |= parity(p);

			omatch_table[i] <<= 1;
			p = odd_table[i] >> j & (LF_POLY_EVEN * 2 + 1);
			omatch_table[i] |= parity(p);
		}
	}


	//find a matches of even and odd contributions
	quicksort(ematch_table, even_table, 0, etab_len - 1);
	quicksort(omatch_table, odd_table, 0, otab_len - 1);

	i = j = 0;
	while(i < etab_len && j < otab_len)
	{
		if(ematch_table[i] == omatch_table[j])
		{
			even_res = even_table[i];
			odd_res = odd_table[j];
			//TODO handle cases where there is more than 1
			break;	
		}
		else if(ematch_table[i] < omatch_table[j])
			++i;
		else if(ematch_table[i] > omatch_table[j])
			++j;
	}


	//perform lf shift and change bit format
	p = odd_res & LF_POLY_ODD;
	p ^= even_res & LF_POLY_EVEN;
	even_res = even_res << 1 | parity(p);

	s->odd = even_res;
	s->even = odd_res;
	
out:
	free(omatch_table);
	free(ematch_table);
	free(odd_table);
	free(even_table);


}

/*
 * lfsr_rollback
 * Rollback the shift register in order to get previous states
 * and eventually the secret key
 */
void
lfsr_rollback(struct Crypto1State * s, uint32_t in, int fb)
{
 	int i, out, nf;
 
	for (i = 7; i >= 0; i ^= 24, --i, i ^= 24)
	{
		s->odd ^= s->even;
		s->even ^= s->odd;
		s->odd ^= s->even;

		out = s->even & 1;
		s->even >>= 1;

		out ^= BIT(in, i);
		out ^= s->odd & LF_POLY_ODD;
		out ^= s->even & LF_POLY_EVEN;
		out = parity(out);
		
		if(fb)
			out ^= filter(s->odd);


		s->even |= out << 23;
	}
}
