#include "crypt.h"




/*******************************************************************
功	能：打印不同算法类型所使用的1.块大小 2.IV向量长度 3.秘钥长度
入	参：无
出	参：无
返回值：无
********************************************************************/
void gld_print(void)
{
	const EVP_CIPHER *cipher;
	cipher = EVP_aes_256_cbc();
	printf("EVP_aes_256_cbc: block_size = %d ,iv_len = %d, ken_len = %d \r\n", cipher->block_size, cipher->iv_len, cipher->key_len);
	cipher = EVP_aes_192_cbc();
	printf("EVP_aes_192_cbc: block_size = %d ,iv_len = %d, ken_len = %d \r\n", cipher->block_size, cipher->iv_len, cipher->key_len);
	cipher = EVP_aes_128_cbc();
	printf("EVP_aes_128_cbc: block_size = %d ,iv_len = %d, ken_len = %d \r\n", cipher->block_size, cipher->iv_len, cipher->key_len);
	cipher = EVP_aes_128_ecb();
	printf("EVP_aes_128_ecb: block_size = %d ,iv_len = %d, ken_len = %d \r\n", cipher->block_size, cipher->iv_len, cipher->key_len);
}


/*******************************************************************
功	能：将数据以十六进制形式打印显示
入	参：1.数据缓存首地址-s	2.数据长度-len
出	参：无
返回值：无
********************************************************************/
void show_hex(unsigned char * s, int len)
{
	for (int i = 0; i<len; i++)
	{
		//以16进制输出，每一个字符占2位。
		printf("%02x", s[i]);
		if (19 == i % 20)
			printf("\n");
	}
	printf("\n\n");
}

/*******************************************************************
功	能：将数据以字符形式打印显示
入	参：1.数据缓存首地址-s	2.数据长度-len
出	参：无
返回值：无
********************************************************************/
void show_str(unsigned char * s, int len)
{
	for (int i = 0; i<len; i++)
	{
		//以字符输出，每一个字符占1位。
		printf("%c", s[i]);
		if (19 == i % 20)
			printf("\n");
	}
	printf("\n\n");
}


/*******************************************************************
功	能：数据加密
入	参：1.算法类型-cipher 2.秘钥-pucKey 3.IV向量-pucIV 
	    4.待加密的明文数据 5.明文数据长度-ulPlainLen
出	参：1.加密后的密文数据-pucCipherText 2.加密后的数据长度-pulCLen
返回值：成功-1 错误-openssl错误码(详情可用openssl自带的ErrCode函数打印)
********************************************************************/
SEC_UINT32 My_CRYPT_encrypt(
	const EVP_CIPHER	*cipher,
	const SEC_UCHAR		*pucKey,
	const SEC_UCHAR		*pucIV,
	SEC_UCHAR			*pucPlainText,
	SEC_INT32			 ulPlainLen,
	SEC_UCHAR			*pucCipherText,
	SEC_INT32			*pulCLen)
{
	SEC_INT32 ulErrCode = 0;
	EVP_CIPHER_CTX ctx = { 0 };
	SEC_UINT32 ulTempClen = 0;


	EVP_CIPHER_CTX_init(&ctx);

	EVP_CIPHER_CTX_set_padding(&ctx, 1);		//padding模式：0为禁用，1为启用


	ulErrCode = EVP_EncryptInit_ex(&ctx, cipher, NULL, pucKey, pucIV);
	if (EVP_SUCCESS != ulErrCode)
	{
		EVP_CIPHER_CTX_cleanup(&ctx);
		return ulErrCode;
	}
	printf("EVP_EncryptInit_ex return %d\r\n", ulErrCode);
	printf("block_size = %d ,iv_len = %d, ken_len = %d \r\n", cipher->block_size, cipher->iv_len, cipher->key_len);


	ulErrCode = EVP_EncryptUpdate(&ctx, pucCipherText, pulCLen, pucPlainText, ulPlainLen);
	if (EVP_SUCCESS != ulErrCode)
	{
		EVP_CIPHER_CTX_cleanup(&ctx);
		return ulErrCode;
	}
	printf("EVP_EncryptUpdate return %d\r\n", ulErrCode);
	printf("outlen = %d\r\n", *pulCLen);

	ulTempClen = *pulCLen;
	ulErrCode = EVP_EncryptFinal_ex(&ctx, (pucCipherText + (*pulCLen)), pulCLen);
	if (EVP_SUCCESS != ulErrCode)
	{
		EVP_CIPHER_CTX_cleanup(&ctx);
		return ulErrCode;
	}

	*pulCLen += ulTempClen;
	printf("加密结果长度： %d\n", *pulCLen);

	EVP_CIPHER_CTX_cleanup(&ctx);

	return EVP_SUCCESS;
}


/*******************************************************************
功	能：数据加密
入	参：1.算法类型-cipher 2.秘钥-pucKey 3.IV向量-pucIV
4.待解密的密文数据 5.密文数据长度-ulPlainLen
出	参：1.解密后的明文数据-pucPlainText 2.解密后的数据长度-pulPLen
返回值：成功-1 错误-openssl错误码(详情可用openssl自带的ErrCode函数打印)
********************************************************************/
SEC_UINT32 My_CRYPT_decrypt(
	const EVP_CIPHER *cipher,
	const SEC_UCHAR  *pucKey,
	const SEC_UCHAR  *pucIV,
	SEC_UCHAR        *pucCipherText,
	SEC_INT32		  ulCLen,
	SEC_UCHAR		 *pucPlainText,
	SEC_INT32		 *pulPLen)
{
	SEC_INT32 ulErrCode = 0;
	EVP_CIPHER_CTX ctx = { 0 };
	SEC_UINT32 ulTempPlen = 0;

	if (0 == ulCLen)
	{
		return -1;
	}

	EVP_CIPHER_CTX_init(&ctx);

	EVP_CIPHER_CTX_set_padding(&ctx, 1);		//padding模式：0为禁用，1为启用

	ulErrCode = EVP_DecryptInit_ex(&ctx, cipher, NULL, pucKey, pucIV);
	if (EVP_SUCCESS != ulErrCode)
	{
		EVP_CIPHER_CTX_cleanup(&ctx);
		return ulErrCode;
	}

	ulErrCode = EVP_DecryptUpdate(&ctx, pucPlainText, pulPLen, pucCipherText, ulCLen);
	if (EVP_SUCCESS != ulErrCode)
	{
		EVP_CIPHER_CTX_cleanup(&ctx);
		return ulErrCode;
	}

	ulTempPlen = *pulPLen;

	ulErrCode = EVP_DecryptFinal_ex(&ctx, pucPlainText + *pulPLen, pulPLen);
	if (EVP_SUCCESS != ulErrCode)
	{
		EVP_CIPHER_CTX_cleanup(&ctx);
		return ulErrCode;
	}

	*pulPLen += ulTempPlen;
	printf("解密结果长度： %d\n", *pulPLen);

	EVP_CIPHER_CTX_cleanup(&ctx);

	return EVP_SUCCESS;
}