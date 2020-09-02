/*  crypto1.c

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

#define BIT(x, n) ((x) >> (n) & 1)

void
crypto1_init(struct Crypto1State *state, uint64_t key)
{
	int i;

	state->odd = state->even = 0;
	for(i = 0; i < 48; i += 2)
	{
		state->odd  = state->odd  << 1 | BIT(key, i + 1);
		state->even = state->even << 1 | BIT(key, i);
	}
}

void
crypto1_get_lfsr(struct Crypto1State *state, uint64_t *lfsr)
{
	*lfsr = 0;
	int i;
	for(i = 0; i < 24; ++i)
	{
		*lfsr = *lfsr << 1 | BIT(state->odd, i);
		*lfsr = *lfsr << 1 | BIT(state->even, i);
	}
}

static uint32_t
crypto1_bit(struct Crypto1State *state, uint32_t in_bit, int fb)
{
	uint32_t nf;

	in_bit = !!in_bit;
	in_bit ^= state->odd & 0x29CE5C;
	in_bit ^= state->even & 0x870804;
	in_bit ^= in_bit >> 16;
	in_bit ^= in_bit >> 8;
	in_bit ^= in_bit >> 4;
	in_bit &= 0xf;
	in_bit = BIT(0x6996, in_bit);

	nf =  0x0D938 >> (state->odd >> 0x10 & 0xf) &  1;
	nf |= 0x1e458 >> (state->odd >> 0x0C & 0xf) &  2;
	nf |= 0x3c8b0 >> (state->odd >> 0x08 & 0xf) &  4;
	nf |= 0x6c9c0 >> (state->odd >> 0x04 & 0xf) &  8;
	nf |= 0xf22c0 >> (state->odd >> 0x00 & 0xf) & 16;
	nf = BIT(0xEC57E80A, nf);

	if(fb)
		in_bit ^= nf;

	state->even = state->even << 1 | in_bit;

	state->odd ^= state->even;
	state->even ^= state->odd;
	state->odd ^= state->even;

	return nf;
}

uint32_t
crypto1_word(struct Crypto1State *state, uint32_t in_word, int fb)
{
	uint32_t i, ret = 0;

	for (i = 24; i < 32; i ^= 24, ++i, i ^= 24)
		ret |= crypto1_bit(state, BIT(in_word, i), fb) << i;

	return ret;
}


/******************************************************************************
 * prng_successor : helper used to obscure the keystream during authentication
 *****************************************************************************/
uint32_t prng_successor(uint32_t x, uint32_t n)
{
	x = x >> 8 & 0xff00ff | (x & 0xff00ff) << 8;
	x = x >> 16 | x << 16;

	while(n--)
	{
		x = x >> 1;
		x |= (BIT(x, 15) ^ BIT(x, 17) ^ BIT(x, 18) ^ BIT(x, 20)) << 31;
	}

	x = x >> 8 & 0xff00ff | (x & 0xff00ff) << 8;
	x = x >> 16 | x << 16;

	return x;
}
