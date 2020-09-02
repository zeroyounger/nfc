/*  crypto1.h

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

#ifndef CRYPTO1_INCLUDED
#define CRYPTO1_INCLUDED

#include <stdint.h>
struct Crypto1State
{
	uint32_t odd, even;
};

void crypto1_init(struct Crypto1State *state, uint64_t key);
uint32_t crypto1_word(struct Crypto1State *state, uint32_t in_word, int fb);
void crypto1_get_lfsr(struct Crypto1State *state, uint64_t *lfsr);
uint32_t prng_successor(uint32_t x, uint32_t n);

#endif
