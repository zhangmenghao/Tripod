/*-
 * Copyright (c) <2010-2017>, Intel Corporation
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * - Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 *
 * - Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in
 *   the documentation and/or other materials provided with the
 *   distribution.
 *
 * - Neither the name of Intel Corporation nor the names of its
 *   contributors may be used to endorse or promote products derived
 *   from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/* Created 2014 by Keith Wiles @ intel.com */

#ifndef _UTILS_H_
#define _UTILS_H_

/**************************************************************************//**
 * The function is a wrapper around strdup() and will free the previous string
 * if the pointer is present.
 */

static __inline__ char *
pg_strdupf(char *str, char *new) {
	if (str) free(str);
	return (new == NULL) ? NULL : strdup(new);
}

/**************************************************************************//**
 * Trim a set of characters like "[]" or "{}" from the start and end of string.
 * The <set> string is a set of two character values to be removed from the string.
 * The <set> string must be an even number of characters long as each set is
 * two characters and can be any characters you want to call a set.
 */

static __inline__ char *
pg_strtrimset(char *str, const char *set)
{
	int len;

	len = strlen(set);
	if ( (len == 0) || (len & 1) )
		return NULL;

	for (; set && (set[0] != '\0'); set += 2) {
		if (*str != *set)
			continue;

		if (*str == *set++)
			str++;

		len = strlen(str);
		if (len && (str[len - 1] == *set) )
			str[len - 1] = '\0';
	}
	return str;
}

uint32_t pg_strparse(char *s,
			    const char *delim,
			    char **entries,
			    uint32_t max_entries);
char *pg_strtrim(char *line);
char *pg_strccpy(char *t, char *f, const char *str);

#endif /* _UTILS_H_ */
