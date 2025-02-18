/*
 * PRESENT crypto implementation 
 * for 80 bit key and encryption only
 * compiled with "gcc (GCC) 5.3.0"
 * serhat
 */
 
/* --PSEUDOCODE from PRESENT paper--
 *
 *	generateRoundKeys()
 *	for i = 1 to 31 do
 *	    addRoundKey(state,Ki)
 *	    sBoxLayer(state)            
 *	    pLayer(state)
 *	end for
 *	addRoundKey(state,K32)		
 */	 

#include<stdio.h>
#include<stdlib.h>  // for malloc() function
#include<string.h>  // for dividing 80bit hex str to 64bits + 16bits
#include<math.h>    // for pow() function 
#include<time.h>    
// typedef unsigned long long int uint64_t;
// typedef unsigned int uint16_t;


//TEST VECTORS
const char *pText = "0000000000000000";    // block for test 
const char *key = "00000000000000000000";  // key for test


unsigned char SBox[16] = {0xc, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD, 0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2};

unsigned int PBox[64] = {
	0,16,32,48,1,17,33,49,2,18,34,50,3,19,35,51,   
    4,20,36,52,5,21,37,53,6,22,38,54,7,23,39,55,
    8,24,40,56,9,25,41,57,10,26,42,58,11,27,43,59,
    12,28,44,60,13,29,45,61,14,30,46,62,15,31,47,63};


//FUNCTION DECLERATIONS	
void multiEncrypt(int num); //no printf
void encrypt(const char *plainText, const char *sKey);



// char *encrypt(const char *plainText, const char *sKey)
void encrypt(const char *plainText, const char *sKey)
{
	printf("Plaintext: %s\n", plainText);
	printf("Key: %s (80-bit)\n", sKey);

	// divide 80bits to 64bits + 16bits
	char skey_left[17];  //left 64 bits of sKey
	char skey_right[5];  //right 16 bits of sKey
	strncpy(skey_left, sKey, 16);
	strncpy(skey_right, sKey + 16, 4);
	skey_left[16] = 0;
	skey_right[4] = 0;

	uint64_t *roundKeyList = (uint64_t *)malloc(sizeof(uint64_t) * 32);
	uint64_t state = (uint64_t)strtoull(plainText, NULL, 16);
	uint64_t key_left = (uint64_t)strtoull(skey_left, NULL, 16);
	uint64_t key_right = (uint16_t)strtoull(skey_right, NULL, 16);
	uint64_t cipherText = 0llu;
	
// generateRoundKeys()
	// K1...K32
	for(int i = 0 ; i < 32 ; i++)
	{
		// Ki = k79k78...k16
		roundKeyList[i] = key_left;
		printf("Round key %d: %llx\n", i+1, roundKeyList[i]);
		
		// [k79k78...k1k0] = [k18k17...k20k19]
		uint16_t temp_right = key_right;
		key_right = (key_left >> 3);  
		key_left = (key_left << 61) | ((uint64_t)temp_right << 45) | (key_left >> 19);
		
		// [k79k78k77k76] = S[k79k78k77k76]
		key_left = ((uint64_t)SBox[key_left>>60] << 60) | (key_left & 0x0fffffffffffffff);

		// [k19k18k17k16k15] = [k19k18k17k16k15] XOR round_counter
		int rCounter = (i + 1);
		key_left ^= rCounter >> 1;
		key_right ^= rCounter << 15;		
	}

	for(int i = 0 ; i < 31 ; i++)
	{
// addRoundKey()	
		state ^= roundKeyList[i];

// SBoxLayer()	
// state = w15...w0 where wi = b4i+3||b4i+2||b4i+1||b4i for 0≤i≤15 	
		uint64_t sState = 0ull;
		for(int i = 0 ; i < 16; i++)
		{
			sState |= (uint64_t)SBox[(state >> 4*i) & 0xf] << (4*i); 
		}
		state = sState;
		
// PLayer()		
		uint64_t pState = 0ull;
		for(int i = 0 ; i < 64; i++)
		{
			pState |= (uint64_t)((state >> i) & 0x1) << PBox[i];
		}
		state = pState;	
		printf("Round Output %d: %llx\n", i+1, state);
	}
	
	state ^= roundKeyList[31];

	cipherText = state;
	printf("Ciphertext: %llx\n", cipherText);
}  


void multiEncrypt(int num)
{
	for(int i = 0 ; i < (int)pow(2, num) ; i++)
	{
		encrypt(pText, key);
	}
}
 
 
int main()
{
	encrypt(pText, key);
	
	// clock_t start = clock(), diff;
	// int pri = 0;
	// printf("Enter power number for encryption: (e.g. 23)\n");
    // scanf("%d", &pri);
	
	// multiEncrypt(pri);
	
	// diff = clock() - start;
	// int msec = diff * 1000 / CLOCKS_PER_SEC;
	// printf("Time taken %d seconds %d milliseconds", msec/1000, msec%1000);
	
	return 0;
}