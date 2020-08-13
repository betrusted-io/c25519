/* Arithmetic mod p = 2^255-19
 * Daniel Beer <dlbeer@gmail.com>, 5 Jan 2014
 *
 * This file is in the public domain.
 */

#include "f25519.h"
#include <stdio.h>

const uint8_t f25519_zero[F25519_SIZE] = {0};
const uint8_t f25519_one[F25519_SIZE] = {1};

void f25519_load(uint8_t *x, uint32_t c)
{
	unsigned int i;

	for (i = 0; i < sizeof(c); i++) {
		x[i] = c;
		c >>= 8;
	}

	for (; i < F25519_SIZE; i++)
		x[i] = 0;
}

void f25519_normalize(uint8_t *x)
{
	uint8_t minusp[F25519_SIZE];
	uint16_t c;
	int i;

	/* Reduce using 2^255 = 19 mod p */
	c = (x[31] >> 7) * 19;
	x[31] &= 127;

	for (i = 0; i < F25519_SIZE; i++) {
		c += x[i];
		x[i] = c;
		c >>= 8;
	}

	/* The number is now less than 2^255 + 18, and therefore less than
	 * 2p. Try subtracting p, and conditionally load the subtracted
	 * value if underflow did not occur.
	 */
	c = 19;

	for (i = 0; i + 1 < F25519_SIZE; i++) {
		c += x[i];
		minusp[i] = c;
		c >>= 8;
	}

	c += ((uint16_t)x[i]) - 128;
	minusp[31] = c;

	/* Load x-p if no underflow */
	f25519_select(x, minusp, x, (c >> 15) & 1);
}

uint8_t f25519_eq(const uint8_t *x, const uint8_t *y)
{
	uint8_t sum = 0;
	int i;

	for (i = 0; i < F25519_SIZE; i++)
		sum |= x[i] ^ y[i];

	sum |= (sum >> 4);
	sum |= (sum >> 2);
	sum |= (sum >> 1);

	return (sum ^ 1) & 1;
}

void f25519_select(uint8_t *dst,
		   const uint8_t *zero, const uint8_t *one,
		   uint8_t condition)
{
	const uint8_t mask = -condition;
	int i;

	for (i = 0; i < F25519_SIZE; i++)
		dst[i] = zero[i] ^ (mask & (one[i] ^ zero[i]));
}

void f25519_add(uint8_t *r, const uint8_t *a, const uint8_t *b)
{
	uint16_t c = 0;
	int i;

	/* Add */
	for (i = 0; i < F25519_SIZE; i++) {
		c >>= 8;
		c += ((uint16_t)a[i]) + ((uint16_t)b[i]);
		r[i] = c;
	}

	/* Reduce with 2^255 = 19 mod p */
	r[31] &= 127;
	c = (c >> 7) * 19;

	for (i = 0; i < F25519_SIZE; i++) {
		c += r[i];
		r[i] = c;
		c >>= 8;
	}
}

void f25519_sub(uint8_t *r, const uint8_t *a, const uint8_t *b)
{
	uint32_t c = 0;
	int i;

	/* Calculate a + 2p - b, to avoid underflow */
	c = 218;
	for (i = 0; i + 1 < F25519_SIZE; i++) {
		c += 65280 + ((uint32_t)a[i]) - ((uint32_t)b[i]);
		r[i] = c;
		c >>= 8;
	}

	c += ((uint32_t)a[31]) - ((uint32_t)b[31]);
	r[31] = c & 127;
	c = (c >> 7) * 19;

	for (i = 0; i < F25519_SIZE; i++) {
		c += r[i];
		r[i] = c;
		c >>= 8;
	}
}

void f25519_neg(uint8_t *r, const uint8_t *a)
{
	uint32_t c = 0;
	int i;

	/* Calculate 2p - a, to avoid underflow */
	c = 218;
	for (i = 0; i + 1 < F25519_SIZE; i++) {
		c += 65280 - ((uint32_t)a[i]);
		r[i] = c;
		c >>= 8;
	}

	c -= ((uint32_t)a[31]);
	r[31] = c & 127;
	c = (c >> 7) * 19;

	for (i = 0; i < F25519_SIZE; i++) {
		c += r[i];
		r[i] = c;
		c >>= 8;
	}
}

#define DSP17_ARRAY_LEN     15  // array size
#define DSP17_BITWIDTH      17  // bitwidth of a single native array element
#define F25519_BITWIDTH     8   // bitwidth of a single F25519 element
typedef long long i64;
typedef i64 operand[DSP17_ARRAY_LEN];  // intermediate results up to 43 bits wide, so use a 64-bit data type

void print_bytearray(const uint8_t *a) {
#ifndef DEBUG
  (void) a;
#endif
  for( int i = F25519_SIZE-1; i >= 0; i-- ) {
    DEBUG_PRINT("%02x", a[i]);
    if( (i % 4) == 0 )
      DEBUG_PRINT(" ");
  }
  DEBUG_PRINT("\n");
}

void print_bytearray_nodebug(const uint8_t *a) {
  for( int i = F25519_SIZE-1; i >= 0; i-- ) {
    printf("%02x", a[i]);
    if( (i % 4) == 0 )
      printf(" ");
  }
  printf("\n");
  for( int i = 0; i < F25519_SIZE; i++ ) {
    if( (i % 8) == 0 )
      printf("\n");
    printf("0x%02x, ", a[i]);
  }
  printf("\n");
}

void print_dsp17(operand a) {
#ifndef DEBUG
  (void) a;
#endif
  for( int i = DSP17_ARRAY_LEN-1; i >= 0; i-- ) {
    DEBUG_PRINT("%06x", a[i]);
    DEBUG_PRINT(" ");
  }
  DEBUG_PRINT("\n");
}

void pack17(const uint8_t *in, operand out) {
  //  0   1   2   3   4   5   6   7   8   9   10  11  12  13  14  15  16  17  18  19  20  21  22  23  24  25  26  27  28  29  30  31  32  33  34  35  36  37  38  -->
  //  ----------------------  in[0] --------------------------------  --------------------------  in[1] ----------------------------  --------- in[2] ----------->
  //  ------------------------------out [0] ----------------------------  ----  out[1] -----------------------------------------------------  ----out[2] ----->
  //  0   1   2   3   4   5   6   7   8   9   10  11  12  13  14  15  16  0   1   2   3   4   5   6   7   8   9   10  11  12  13  14  15  16
  
  // make sure the destination array is zeroed
  for(int i = 0; i < DSP17_ARRAY_LEN; i++) {
    out[i] = 0;
  }
  // now fill in bit by bit, the naive but easily correct way
  for(int i = 0; i < 255; i++) {
    if(in[i / F25519_BITWIDTH] & (1 << (i % F25519_BITWIDTH))) {
      out[i / DSP17_BITWIDTH] |= (1 << (i % DSP17_BITWIDTH));
    }
  }
}

void unpack17(const operand in, uint8_t *out) {
   for(int i = 0; i < F25519_SIZE; i++) {
      out[i] = 0;
   }
   for(int i = 0; i < 255; i++) {
     if(in[i / DSP17_BITWIDTH] & (1 << (i % DSP17_BITWIDTH))) {
       out[i / F25519_BITWIDTH] |= (1 << (i % F25519_BITWIDTH));
     }
   }
}

void f25519_add__hw(uint8_t *r, const uint8_t *a_c, const uint8_t *b_c) {
   uint8_t a[F25519_SIZE];
   uint8_t b[F25519_SIZE];
  
   // copy const inputs to variable array
   for(int i = 0; i < F25519_SIZE; i++) {
     a[i] = a_c[i];
     b[i] = b_c[i];
   }
   
   f25519_normalize(a);
   f25519_normalize(b);

   operand a_dsp;
   operand b_dsp;
   operand p;
   
   pack17(a, a_dsp);
   pack17(b, b_dsp);

   for(int i=0; i < 15; i++ ) {
     p[i] = a[i] + b[i];
   }
   
}

void f25519_mul__hw(uint8_t *o, const uint8_t *a_c, const uint8_t *b_c) {
   operand a_dsp;
   operand a_bar_dsp;
   operand b_dsp;

   uint8_t a[F25519_SIZE];
   uint8_t b[F25519_SIZE];

   // copy const inputs to variable array
   for(int i = 0; i < F25519_SIZE; i++) {
     a[i] = a_c[i];
     b[i] = b_c[i];
   }
   
   DEBUG_PRINT("a:\n");
   print_bytearray(a);
   f25519_normalize(a); // all inputs must be normalized
   DEBUG_PRINT("a_norm:\n");
   print_bytearray(a);
   f25519_normalize(b);
   
   pack17(a, a_dsp);
   pack17(b, b_dsp);

   DEBUG_PRINT("a_dsp:\n");
   print_dsp17(a_dsp);
   DEBUG_PRINT("b_dsp:\n");
   print_dsp17(b_dsp);
   // initialize the a_bar set of data
   for( int i = 0; i < DSP17_ARRAY_LEN; i++ ) {
      a_bar_dsp[i] = a_dsp[i] * 19;
   }
   operand p;
   for( int i = 0; i < DSP17_ARRAY_LEN; i++ ) { p[i] = 0; }

   // core multiply
   for( int col = 0; col < 15; col++ ) {
     for( int row = 0; row < 15; row++ ) {
       if( row >= col ) {
	 p[row] += a_dsp[row-col] * b_dsp[col];
       } else {
	 p[row] += a_bar_dsp[15+row-col] * b_dsp[col];
       }
     }
   }

   i64 overflow = 1;
   int prop_iteration = 0;
   int had_overflow = 0;
   operand prop;
   while( prop_iteration < 2 ) { // do it twice even if we don't have to, because constant time
     // first time to propagate the raw carry
     // second time to catch if the carry propagate carried
     // third time to propagate the case of the 2^255-19 <= result <= 2^255
     had_overflow = 0;
     DEBUG_PRINT("**p:\n");
     print_dsp17(p);

     // sum the partial sums
     //   prop[0] = (p[0] & 0x1ffff) + (( ((p[14] >> 17) * 19) & 0x1ffff) + ( ((p[13] >> 34) * 19) & 0x1ffff));
     //   prop[1] = (p[1] & 0x1ffff) + ((p[0] >> 17) & 0x1ffff) + ( ((p[14] >> 34) * 19) & 0x1ffff);
     prop[0] = (p[0] & 0x1ffff) +
       (((p[14] * 1) >> 17) & 0x1ffff) * 19 +
       (((p[13] * 1) >> 34) & 0x1ffff) * 19;
     prop[1] = (p[1] & 0x1ffff) +
       ((p[0] >> 17) & 0x1ffff) +
       (((p[14] * 1) >> 34) & 0x1ffff) * 19;
     for(int bitslice = 2; bitslice < 15; bitslice += 1) {
       prop[bitslice] = (p[bitslice] & 0x1ffff) + ((p[bitslice - 1] >> 17) & 0x1ffff) + ((p[bitslice - 2] >> 34));
     }

     DEBUG_PRINT("**prop:\n");
     print_dsp17(prop);

     // propagate the carries
     for(int i = 0; i < 15; i++) {
       if( i+1 < 15 ) {
	 prop[i+1] = (prop[i] >> 17) + prop[i+1];
	 prop[i] = prop[i] & 0x1ffff;
       }
     }
     DEBUG_PRINT("**carry:\n");
     print_dsp17(prop);
     
     // prep for the next iteration
     for(int i = 0; i < 15; i++ ) {
       p[i] = prop[i];
     }

     if( prop_iteration == 0 ) {
       // check special case of 2^255 >= result > 2^255 - 19
       int special_case = 1;
       for( int i = 1; i < 15; i++) {
	 if(p[i] != 0x1ffff)
	   special_case = 0;
       }
       if(special_case) {
	 DEBUG_PRINT("maybe special case\n");
	 if( p[0] >= 0x1ffed ) { // p % 2^255-19 => 0. >= or > doesn't matter b/c 0x7ff..fed wraps to 0
	   printf("special case caught!\n");
	   p[0] = p[0] + 19; // push to the next modulus
	   //for( int i = 1; i < 15; i++ ) {
	   //  p[i] = p[i] + 1; // propagate carries
	   //}
	 } 
       } else if( p[14] & 0x20000 ) {
	 p[0] = p[0] + 19;
	 p[14] &= 0x1ffff;
       }
     }
     
     prop_iteration++;

   }

   unpack17(prop, o);
}

void f25519_mul__distinct(uint8_t *r, const uint8_t *a, const uint8_t *b)
{
	uint32_t c = 0;
	int i;

	for (i = 0; i < F25519_SIZE; i++) {
		int j;

		c >>= 8;
		for (j = 0; j <= i; j++)
			c += ((uint32_t)a[j]) * ((uint32_t)b[i - j]);

		for (; j < F25519_SIZE; j++)
			c += ((uint32_t)a[j]) *
			     ((uint32_t)b[i + F25519_SIZE - j]) * 38;

		r[i] = c;
	}

	r[31] &= 127;
	c = (c >> 7) * 19;

	for (i = 0; i < F25519_SIZE; i++) {
		c += r[i];
		r[i] = c;
		c >>= 8;
	}
}

void f25519_mul(uint8_t *r, const uint8_t *a, const uint8_t *b)
{
	uint8_t tmp[F25519_SIZE];

	f25519_mul__distinct(tmp, a, b);
	f25519_copy(r, tmp);
}

void f25519_mul_c(uint8_t *r, const uint8_t *a, uint32_t b)
{
	uint32_t c = 0;
	int i;

	for (i = 0; i < F25519_SIZE; i++) {
		c >>= 8;
		c += b * ((uint32_t)a[i]);
		r[i] = c;
	}

	r[31] &= 127;
	c >>= 7;
	c *= 19;

	for (i = 0; i < F25519_SIZE; i++) {
		c += r[i];
		r[i] = c;
		c >>= 8;
	}
}

void f25519_inv__distinct(uint8_t *r, const uint8_t *x)
{
	uint8_t s[F25519_SIZE];
	int i;

	/* This is a prime field, so by Fermat's little theorem:
	 *
	 *     x^(p-1) = 1 mod p
	 *
	 * Therefore, raise to (p-2) = 2^255-21 to get a multiplicative
	 * inverse.
	 *
	 * This is a 255-bit binary number with the digits:
	 *
	 *     11111111... 01011
	 *
	 * We compute the result by the usual binary chain, but
	 * alternate between keeping the accumulator in r and s, so as
	 * to avoid copying temporaries.
	 */

	/* 1 1 */
	f25519_mul__distinct(s, x, x);
	f25519_mul__distinct(r, s, x);

	/* 1 x 248 */
	for (i = 0; i < 248; i++) {
		f25519_mul__distinct(s, r, r);
		f25519_mul__distinct(r, s, x);
	}

	/* 0 */
	f25519_mul__distinct(s, r, r);

	/* 1 */
	f25519_mul__distinct(r, s, s);
	f25519_mul__distinct(s, r, x);

	/* 0 */
	f25519_mul__distinct(r, s, s);

	/* 1 */
	f25519_mul__distinct(s, r, r);
	f25519_mul__distinct(r, s, x);

	/* 1 */
	f25519_mul__distinct(s, r, r);
	f25519_mul__distinct(r, s, x);
}

void f25519_inv(uint8_t *r, const uint8_t *x)
{
	uint8_t tmp[F25519_SIZE];

	f25519_inv__distinct(tmp, x);
	f25519_copy(r, tmp);
}

/* Raise x to the power of (p-5)/8 = 2^252-3, using s for temporary
 * storage.
 */
static void exp2523(uint8_t *r, const uint8_t *x, uint8_t *s)
{
	int i;

	/* This number is a 252-bit number with the binary expansion:
	 *
	 *     111111... 01
	 */

	/* 1 1 */
	f25519_mul__distinct(r, x, x);
	f25519_mul__distinct(s, r, x);

	/* 1 x 248 */
	for (i = 0; i < 248; i++) {
		f25519_mul__distinct(r, s, s);
		f25519_mul__distinct(s, r, x);
	}

	/* 0 */
	f25519_mul__distinct(r, s, s);

	/* 1 */
	f25519_mul__distinct(s, r, r);
	f25519_mul__distinct(r, s, x);
}

void f25519_sqrt(uint8_t *r, const uint8_t *a)
{
	uint8_t v[F25519_SIZE];
	uint8_t i[F25519_SIZE];
	uint8_t x[F25519_SIZE];
	uint8_t y[F25519_SIZE];

	/* v = (2a)^((p-5)/8) [x = 2a] */
	f25519_mul_c(x, a, 2);
	exp2523(v, x, y);

	/* i = 2av^2 - 1 */
	f25519_mul__distinct(y, v, v);
	f25519_mul__distinct(i, x, y);
	f25519_load(y, 1);
	f25519_sub(i, i, y);

	/* r = avi */
	f25519_mul__distinct(x, v, a);
	f25519_mul__distinct(r, x, i);
}
