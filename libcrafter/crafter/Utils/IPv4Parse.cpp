/*
Copyright (c) 2012, Esteban Pellegrino
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.
    * Neither the name of the <organization> nor the
      names of its contributors may be used to endorse or promote products
      derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL ESTEBAN PELLEGRINO BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/


#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "IPv4Parse.h"

static
int ipv4_parse_sv (ipv4_parse_ctx *ctx, int idx, char *sv)

{
	int wc = 0;
	int x  = 0;

	// check if single value is wildcard (entire range from 0-255)

	wc = (strchr(sv, '*') == NULL ? 0 : 1);
	if(wc)
	{
		if(strlen(sv) != 0x1)
		{
			return(-1);
		}

		for(x=0; x<= 0xFF; ++x)
		{
			ctx->m_state[idx] [x] = 1;
		}
	}
	// single value (ex. "1", "2", "192", "10")

	else
	{
		ctx->m_state[idx] [(unsigned char) atoi(sv)] = 1;
	}

	return(0);

}

/*
 * ipv4_parse_r()
 *
 *
 */

static
int ipv4_parse_r (ipv4_parse_ctx *ctx, int idx, char *r)
{
	unsigned char hi = 0;
	unsigned char lo = 0;
	char *p1 = NULL;
	int x = 0;

	// parse low value & high value from range
	p1 = strchr(r, '-');
	*p1 = '\0';
	++p1;

	lo = (unsigned char) atoi(r);
	hi = (unsigned char) atoi(p1);

	// if low value is larger that high value,
	// return error (ex. "200-100").

	if(lo>=hi)
	{
		return(-1);
	}

	// enable range
	for(x=lo; x<=hi; ++x)
	{
		ctx->m_state[idx] [x] = 1;
	}

	return(0);
}

/*
 * ipv4_parse_tok()
 *
 *
 */

static
int ipv4_parse_tok (ipv4_parse_ctx *ctx, int idx, char *tok)
{
	int ret = 0;

	// does value have a dash indicating range in it?
	// (ex. "1-5"); if not, treat as single value (ex "1", "2", "*")
	// if so, treat as range (ex. "1-5")

	ret = (strchr(tok, '-') == NULL) ?
	ipv4_parse_sv(ctx, idx, tok) :
	 ipv4_parse_r (ctx, idx, tok);

	return(ret);
}

/*
 * ipv4_parse_octet()
 *
 *
 */

static
int ipv4_parse_octet (ipv4_parse_ctx *ctx, int idx, char *octet)
{
	char *tok = NULL;
	int ret = 0;

	// parse octet by comma character, if comma
	// character present

	tok = strtok(octet, ",");
	if(tok != NULL)
	{
		while(tok != NULL)
		{
			// treat each comma separated value as a
			// range or single value (like, "2-100", "7", etc)
			ret = ipv4_parse_tok(ctx, idx, tok);
			if(ret < 0)
			{
				return(-1);
			}

			tok = strtok(NULL, ",");
		}
	}
	// otherwise, no comma is present, treat as a range
	// or single value (like, "2-100", "7", etc)
	else
	{
		ret = ipv4_parse_tok(ctx, idx, octet);
		if(ret < 0)
		{
			return(-1);
		}
	}

	return(0);
}

/*
 * ipv4_parse_ctx_init()
 *
 * the ip range is treated as four arrays of 256
 * unsigned char value. each array represents one
 * of the four octets in an ip address. Positions
 * in the array are marked as either one or zero.
 * Positions are marked as one if those values were
 * supplied in the range. For example:
 *
 * char *range = "10.1.1.1";
 *
 * would result in the 10th byte of the 1st array
 * being set to the value of one, whie the 1st
 * byte of the 2nd, 3rd and 4th arrays being set to
 * one.
 *
 * Once the range has been completely parsed and
 * all values stored in the arrays (the state), a
 * series of for loops can be used to iterate
 * through the range.
 *
 * IP address range parser for nmap-style command
 * line syntax.
 *
 * Example:
 *
 * "192.168.1,2,3,4-12,70.*"
 *
 *
 *
 */

int ipv4_parse_ctx_init (ipv4_parse_ctx *ctx, char *range)
{
	char *oc[4];

	if(ctx == NULL || range == NULL)
	{
		return(-1);
	}

	memset(ctx, 0x00, sizeof(ipv4_parse_ctx));

	// parse ip address range into 4 octets

	if((oc[0] = strtok(range, ".")) == NULL ||
	   (oc[1] = strtok(NULL,  ".")) == NULL ||
	   (oc[2] = strtok(NULL,  ".")) == NULL ||
	   (oc[3] = strtok(NULL,  ".")) == NULL)
	{
		return(-1);
	}

	// parse each octet

	if(ipv4_parse_octet(ctx, 0, oc[0]) < 0 ||
	   ipv4_parse_octet(ctx, 1, oc[1]) < 0 ||
	   ipv4_parse_octet(ctx, 2, oc[2]) < 0 ||
	   ipv4_parse_octet(ctx, 3, oc[3]) < 0)
	{
		return(-1);
	}

	return(0);
}

/*
 * ipv4_parse_next_addr()
 *
 * this function is used to iterate through the
 * previously parsed IP address range.
 *
 *
 *
 */
int ipv4_parse_next (ipv4_parse_ctx *ctx, unsigned int *addr)
{
	if(ctx == NULL || addr == NULL)
	{
		return(-1);
	}

	for( ; ctx->m_index[0] <= 0xFF; ++ctx->m_index[0])
	{
		if(ctx->m_state[0] [ctx->m_index[0]] != 0)
		{
			for( ; ctx->m_index[1] <= 0xFF; ++ctx->m_index[1])
			{
				if(ctx->m_state[1] [ctx->m_index[1]] != 0)
				{
					for( ; ctx->m_index[2] <= 0xFF; ++ctx->m_index[2])
					{
						if(ctx->m_state[2] [ctx->m_index[2]] != 0)
						{
							for( ; ctx->m_index[3] <= 0xFF; ++ctx->m_index[3])
							{
								if(ctx->m_state[3] [ctx->m_index[3]] != 0)
								{
									*addr = ((ctx->m_index[0] << 0) & 0x000000FF) ^ ((ctx->m_index[1] << 8) & 0x0000FF00) ^ ((ctx->m_index[2] << 16) & 0x00FF0000) ^ ((ctx->m_index[3] << 24) & 0xFF000000);
									++ctx->m_index[3];

									return(0);
								}
							}
							ctx->m_index[3] = 0;
						}
					}
					ctx->m_index[2] = 0;
				}
			}
			ctx->m_index[1] = 0;
		}
	}

	return(-1);
}
