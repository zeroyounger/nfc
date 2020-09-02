/*  crapto1.h

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

#ifndef CRAPTO1_INCLUDED
#define CRAPTO1_INCLUDED
#include <stdint.h>
struct Crypto1State;

void lfsr_recovery(struct Crypto1State * s, uint32_t ks2, uint32_t ks3);
void lfsr_rollback(struct Crypto1State * s, uint32_t in, int fb);

#endif
