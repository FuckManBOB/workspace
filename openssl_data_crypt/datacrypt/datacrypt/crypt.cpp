#include "crypt.h"




/*******************************************************************
��	�ܣ���ӡ��ͬ�㷨������ʹ�õ�1.���С 2.IV�������� 3.��Կ����
��	�Σ���
��	�Σ���
����ֵ����
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
��	�ܣ���������ʮ��������ʽ��ӡ��ʾ
��	�Σ�1.���ݻ����׵�ַ-s	2.���ݳ���-len
��	�Σ���
����ֵ����
********************************************************************/
void show_hex(unsigned char * s, int len)
{
	for (int i = 0; i<len; i++)
	{
		//��16���������ÿһ���ַ�ռ2λ��
		printf("%02x", s[i]);
		if (19 == i % 20)
			printf("\n");
	}
	printf("\n\n");
}

/*******************************************************************
��	�ܣ����������ַ���ʽ��ӡ��ʾ
��	�Σ�1.���ݻ����׵�ַ-s	2.���ݳ���-len
��	�Σ���
����ֵ����
********************************************************************/
void show_str(unsigned char * s, int len)
{
	for (int i = 0; i<len; i++)
	{
		//���ַ������ÿһ���ַ�ռ1λ��
		printf("%c", s[i]);
		if (19 == i % 20)
			printf("\n");
	}
	printf("\n\n");
}


/*******************************************************************
��	�ܣ����ݼ���
��	�Σ�1.�㷨����-cipher 2.��Կ-pucKey 3.IV����-pucIV 
	    4.�����ܵ��������� 5.�������ݳ���-ulPlainLen
��	�Σ�1.���ܺ����������-pucCipherText 2.���ܺ�����ݳ���-pulCLen
����ֵ���ɹ�-1 ����-openssl������(�������openssl�Դ���ErrCode������ӡ)
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

	EVP_CIPHER_CTX_set_padding(&ctx, 1);		//paddingģʽ��0Ϊ���ã�1Ϊ����


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
	printf("���ܽ�����ȣ� %d\n", *pulCLen);

	EVP_CIPHER_CTX_cleanup(&ctx);

	return EVP_SUCCESS;
}


/*******************************************************************
��	�ܣ����ݼ���
��	�Σ�1.�㷨����-cipher 2.��Կ-pucKey 3.IV����-pucIV
4.�����ܵ��������� 5.�������ݳ���-ulPlainLen
��	�Σ�1.���ܺ����������-pucPlainText 2.���ܺ�����ݳ���-pulPLen
����ֵ���ɹ�-1 ����-openssl������(�������openssl�Դ���ErrCode������ӡ)
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

	EVP_CIPHER_CTX_set_padding(&ctx, 1);		//paddingģʽ��0Ϊ���ã�1Ϊ����

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
	printf("���ܽ�����ȣ� %d\n", *pulPLen);

	EVP_CIPHER_CTX_cleanup(&ctx);

	return EVP_SUCCESS;
}