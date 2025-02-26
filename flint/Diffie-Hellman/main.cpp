#include <string.h>
#include <stdio.h>
#include <stdlib.h>

// FLINT bignum libraries, from "Cryptography in C and C++" by Michael Welschenbach, Apress
#include "../src/flintpp.h"
#include "../src/random.h"

int InitRand (STATEPRNG& , const char*, int, int, int);
LINT RandLINT (int l, STATEPRNG& xrstate);

int main(int, char **)
{
	// length of secret to be exchanged
	unsigned short bits = 2048;

    // long long int P, G, x, a, y, b, ka, kb;
	if(bits <= 16) 
	{
		printf("Bit length too small, must be greater than 16.\n");
		exit(0);
	}
	if(bits > 4096)
	{
		printf("Bit length too great, must be 4096 or less.\n");
		exit(0);
	}

	LINT P, G, a, b, x, y, ka, kb;

	STATEPRNG prngState;
	int missingBits = InitRand(prngState, "", 0, 200, FLINT_RNDRMDSHA1);
	if(missingBits > 0)
	{
		printf("Warning:  Insufficient entropy for generating RSA keys, %i bits short.\n\n", missingBits);
	}
	else if(missingBits < 0)
	{
		printf("Warning:  Selected prng not available.\n\n");
		return -1;
	}
  
	// pick the modulus prime from a list (2048 bit from RFC 3526), this is public 
	P = LINT("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B2"
		"2514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7E"
		"C6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45"
		"B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F3562085"
		"52BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180"
		"E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898"
		"FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF", 16);
	printf("P 0x%s\n\n", P.hexstr());

	// pick the primitive root (the generator, matches prime from RFC 3526)), this is public
	G = LINT("2", 16);
	printf("G 0x%s\n\n", G.hexstr());

    // Alice will choose the private key a
	a = RandLINT(bits, prngState);
	printf("a 0x%s\n\n", a.hexstr());

	// x = G^a mod P
    x = mexpkm(G, a, P); // gets the generated key
	printf("x 0x%s\n\n", x.hexstr());

    // Bob will choose the private key b
	b = RandLINT(bits, prngState);
	printf("b 0x%s\n\n", b.hexstr());

	// y = G^b mod P
    y = mexpkm(G, b, P); // gets the generated key
	printf("y 0x%s\n\n", y.hexstr());

	// x and y are exchanged; these encapsulate a and b securely

	// a is mixed with y, and b is mixed with x, generating the shared secret
    // ka should equal kb
    ka = mexpkm(y, a, P); // Alice's computed secret
	printf("ka 0x%s\n\n", ka.hexstr());
    kb = mexpkm(x, b, P); // Bob's computed secret
	printf("kb 0x%s\n\n", kb.hexstr());

	if(ka == kb) printf("Secrets match, exchange successful\n");

    return 0;
}
