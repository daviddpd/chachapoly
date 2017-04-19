#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <stdint.h>
#include <sodium.h>
#include <getopt.h>
#include <sys/stat.h>
#include "chachapoly.h"

typedef struct
{
	char * infile;
	char * outfile;
} UsageConfig;


/* The Curve 25519 donna doesn't have a header file */
extern void curve25519_donna(unsigned char *output, const unsigned char *a,
                             const unsigned char *b);


/* Untility functions */ 

void 
_usage(char *p) {
	printf ("%s --infile DATAFILE\n", p);
	printf ("   -f --infile   FILE          file to encrypt.\n");
//	printf ("   -o --outfile FILE           file to write\n");
	exit(1);
}

void 
_args(int argc, char**argv, UsageConfig *uc) {
	int ch;

	struct option longopts[] = {
		{	"infile",	required_argument,	NULL,	'f'	},
//		{	"outfile",		required_argument,	NULL,	'o'	},

		/*  remember a zero line, else 
			getopt_long segfaults with unknown options */
	    {NULL, 			0, 					0, 		0	}
			
	};

	
	while ((ch = getopt_long(argc, argv, "f:o:", longopts, NULL)) != -1) {
		switch (ch) {
			case 'f':
				uc->infile = optarg;
			break;
			case 'o':
				uc->outfile = optarg;
			break;
			default:
    			_usage(argv[0]);
			break;
		}
	}
	argc -= optind;
	argv += optind;


}

void print_bin2hex(unsigned char * x, int len) {
	int i,b=0;
	printf ( "\n %4s: ", " " );		
	
	for (i=0; i<len; i++) {
		printf ( "%02x", x[i] );
		if ( (i>0) && ( (i+1)%4 == 0 ) ) { printf (" "); b++; } 
		if ( (i>0) && (b>6) ) { 
        	printf ( "\n %4s: ", " " );		
		    b=0;
		}		
	}
	printf ("\n");

}

void 
hexprint ( unsigned char *str, uint32_t len ){
	int i;
	unsigned char p;
	printf ( "\n %4s: ", " " );		

	for (i=0; i<len; i++) {
		p = str[i];
		if ( p == 0 ) {
			printf ("_");
		} else if ( p < 32 ) {
			printf (" ");
		} else {
			printf ("%c", p);
		}
		
		if ( (i > 0 ) && (i % 42) == 0 ) {
			printf ( "\n %4s: ", " " );		
		}
	}

	printf ("\n");

}

int main(int argc, char**argv)
{

    
	int i;
	
	char *_lyrics;
	int L;	
	FILE *fp=0;
	struct stat fs;

	static const uint8_t basepoint[32] = {9};

	unsigned char mypublic[32];
	unsigned char mysecret[32];

	unsigned char theirpublic[32];
	unsigned char theirsecret[32];
	UsageConfig uc;	
    _args(argc, argv, &uc);


    fp = fopen(uc.infile,"r");
    if ( fp == NULL ) {
		_usage(argv[0]);
        return 1;
    } else {
        stat(uc.infile, &fs);
        _lyrics=(char *)calloc(fs.st_size,sizeof(unsigned char));
        fread(_lyrics, sizeof (unsigned char), fs.st_size, fp );
        L=fs.st_size;
        fclose(fp);		
    }


	for (i=0; i<32; i++){
		mypublic[i] = 0;
		mysecret[i] =0;
		theirpublic[i]=0;
		theirsecret[i]=0;	
	}

	arc4random_buf(&mysecret, 32);
	arc4random_buf(&theirsecret, 32);
	uint8_t nonce[12]; 

	arc4random_buf(&nonce, 12);
	

	unsigned char shared[32];
	unsigned char shared2[32];


	curve25519_donna((unsigned char *)&mypublic, (unsigned char *)&mysecret, (unsigned char *)&basepoint);
	printf (" My Public Key : " );
	print_bin2hex((unsigned char *)&mypublic, 32);

	printf (" My Secret Key : " );
	print_bin2hex((unsigned char *)&mysecret, 32);
    printf ("\n");

	curve25519_donna((unsigned char *)&theirpublic, (unsigned char *)&theirsecret, (unsigned char *)&basepoint);
	printf (" Their Public Key : " );
	print_bin2hex((unsigned char *)&theirpublic, 32);

	printf (" Their Secret Key : " );
	print_bin2hex((unsigned char *)&theirsecret, 32);
    printf ("\n");
	
	curve25519_donna((unsigned char *)&shared, (unsigned char *)&mysecret, (unsigned char *)&theirpublic);
	printf (" Shared Key : " );
	print_bin2hex((unsigned char *)&shared, 32);

	curve25519_donna((unsigned char *)&shared2, (unsigned char *)&theirsecret, (unsigned char *)&mypublic );
	printf (" Shared Key 2: " );
	print_bin2hex((unsigned char *)&shared2, 32);
    printf ("\n");

	
	printf (" Nonce : " ) ;
	print_bin2hex((unsigned char *)&nonce, 12);
    printf ("\n");

	
	unsigned char *data=calloc(L+16,sizeof(unsigned char));

	printf ( " ===================> chacha-poly_crypt IETF C99 <================================ \n " );
    struct chachapoly_ctx ctx;
	unsigned char additional_data[32] = { 'D', 'P', 'D', 0,0,0,0,0,0,0,0,0,0,0,0,0, 'D', 'P', 'D', 0,0,0,0,0,0,0,0,0,0,0,0,0 };
	unsigned long long additional_data_length = 32;

    chachapoly_init(&ctx, &shared, 256);
    chachapoly_crypt(&ctx, &nonce, &additional_data, additional_data_length, _lyrics, L, data, data+L, 16, 1);
/*
	printf ( " ===================> encrypted message <================================ \n" );
	hexprint( data, L+16);
	print_bin2hex( data, L+16);
*/
	printf ( "\nPoly1305 Tag  :" );                                     
	print_bin2hex(data+L, 16);
	
	printf("\n");
	printf("\n");

	
	printf ( " ===================> AEAD IETF LibSodium <================================ \n " );
		

	unsigned char *ciphertext = calloc( L + crypto_aead_chacha20poly1305_ABYTES, sizeof(unsigned char) );
	unsigned long long ciphertext_len = L + crypto_aead_chacha20poly1305_ABYTES;

	unsigned char *decrypted = calloc( L , sizeof(unsigned char) );
	unsigned long long decrypted_len = L ;

	
	crypto_aead_chacha20poly1305_ietf_encrypt(ciphertext, &ciphertext_len,
										 (const unsigned char *)_lyrics, L,
										 (const unsigned char *)&additional_data, additional_data_length,
										 NULL, nonce, (unsigned char *) &shared);
									 
/*
	printf ( " ===================> encrypted message <================================ \n" );
	hexprint( ciphertext, ciphertext_len);
	print_bin2hex( ciphertext, ciphertext_len);
*/	
	printf ( "\nPoly1305 Tag (libsodium ) : " );
	print_bin2hex(ciphertext+ (ciphertext_len-16), 16);
	printf ( "\nPoly1305 Tag (rfc7539/c99): " );
	print_bin2hex(data+L, 16);

	printf ( "\nComparing Poly1305 Tags : " );
    for (i=0; i<16; i++) {
        if ( ciphertext[ciphertext_len-16+i] != (data+L)[i] ) 
        { 
            printf ( "Error, not matching @ %d\n", i );
            break;
        }
    }
    if (i == 16) { printf ("OK!\n"); }

	decrypted = calloc( L , sizeof(unsigned char) );
	decrypted_len = L ;


	if (crypto_aead_chacha20poly1305_ietf_decrypt(decrypted, &decrypted_len,
											 NULL,
											 ciphertext, ciphertext_len,
											 (unsigned char *)&additional_data, additional_data_length,
//											 NULL, 0,
											 nonce, (unsigned char *)&shared2) == 0) 
		{
			printf ( " ======================================================================== \n " );
			printf ( "libSoduim -> libSoduim - Decryption Succeed! \n" );
        	hexprint( decrypted, decrypted_len);
			
		} else {
			printf ( "libSoduim -> libSoduim - Decryption Failed! \n" );	
	
		}

    free(decrypted);
	decrypted = calloc( L , sizeof(unsigned char) );
	decrypted_len = L ;


//    chachapoly_crypt(&ctx, &nonce,      &additional_data, additional_data_length, _lyrics, L, data, data+L, 16, 1);    
//    chachapoly_crypt(&ctx, nonce,       ad,               12,                     pt,    114, ct,   tag,    16, 1);
//    chachapoly_crypt(&ctx, nonce,       ad,               12,                     ct,    114, pt,   tag,    16, 0);

	printf ( " === encrypted text ===================================================================== \n " );
   	hexprint( data, L+16);        	
	print_bin2hex(data, L+16);

    chachapoly_init(&ctx, &shared2, 256);
	if ( chachapoly_crypt(&ctx, &nonce, 
	                    &additional_data, additional_data_length, 
                	    data, L,
                	    decrypted, data+L, 
                	    16, 0) == 0) 
		{ 
			printf ( " ======================================================================== \n " );
			printf ( "chacha-poly-c99 -> libSoduim - Decryption Succeed !!! \n" );		
        	hexprint( decrypted, L);        	
		} else {
			printf ( "chacha-poly-c99 -> libSoduim - Decryption Failed! ********* \n" );
		}

}