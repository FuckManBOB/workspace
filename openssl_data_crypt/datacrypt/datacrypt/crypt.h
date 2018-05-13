#ifndef __CRYPT__H
#define __CRYPT__H

#include "openssl\aes.h"
#include "openssl\evp.h"
#include "openssl\rand.h"



typedef  int	       SEC_INT32;
typedef  unsigned int  SEC_UINT32;
typedef  unsigned char SEC_UCHAR;


#define EVP_SUCCESS 1





void gld_print(void);
void show_hex(unsigned char * s, int len);
void show_str(unsigned char * s, int len);

SEC_UINT32 My_CRYPT_encrypt(
	const EVP_CIPHER	*cipher,
	const SEC_UCHAR		*pucKey,
	const SEC_UCHAR		*pucIV,
	SEC_UCHAR			*pucPlainText,
	SEC_INT32			 ulPlainLen,
	SEC_UCHAR			*pucCipherText,
	SEC_INT32			*pulCLen);

SEC_UINT32 My_CRYPT_decrypt(
	const EVP_CIPHER *cipher,
	const SEC_UCHAR  *pucKey,
	const SEC_UCHAR  *pucIV,
	SEC_UCHAR        *pucCipherText,
	SEC_INT32		  ulCLen,
	SEC_UCHAR		 *pucPlainText,
	SEC_INT32		 *pulPLen);


#endif