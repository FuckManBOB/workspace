// datacrypt.cpp : Defines the entry point for the console application.
//

#include <stdio.h>

#include "crypt.h"



const EVP_CIPHER *cipher = NULL;



//明文和明文间的关系
//密文长度 = ((明文长度/分组长度) + 1) * 分组长度

int main()
{
	int ret = 0, which = 1;
	const EVP_CIPHER *cipher = NULL;
	unsigned char key[24] = { 0 }, iv[8] = { 0 }, in[100] = { 0 }, out[112] = { 0 }, de[100] = { 0 };
	int i = 0, outl = 0, total = 0;

	for (i = 0; i<24; i++)
	{
		memset(&key[i], i, 1);
	}
	for (i = 0; i<8; i++)
	{
		memset(&iv[i], i, 1);
	}
	for (i = 0; i<100; i++)
	{
		//memset(&in[i], i + 1, 1);
		in[i] = 'a' + i % 26;
	}

	cipher = cipher = EVP_aes_256_cbc();

	printf("原文:\n");
	//show_hex(in, 100);
	show_str(in, 100);
	ret = My_CRYPT_encrypt(cipher, key, iv, in, 100, out, &outl);
	if (EVP_SUCCESS != ret)
	{
		printf("My_CRYPT_encrypt Fail\n");
	}
	printf("加密后:\n");
	//show_hex(out, outl);
	show_str(out, outl);		


	ret = My_CRYPT_decrypt(cipher, key, iv, out, outl, de, &total);
	if (EVP_SUCCESS != ret)
	{
		printf("My_CRYPT_decrypt Fail\n");
	}
	printf("解密结果：\n");
	//show_hex(de, total);
	show_str(de, total);

	return 0;
}
