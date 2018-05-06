//
//  main.m
//  pandorablowfish
//
//  Created by Ethan Arbuckle on 4/28/18.
//  Copyright © 2018 DataTheorem. All rights reserved.
//

#import <Foundation/Foundation.h>
#include "blowfish.h"

static char i2h[16] = "0123456789abcdef";
static char h2i[256] = {
	['0'] = 0,
	['1'] = 1,
	['2'] = 2,
	['3'] = 3,
	['4'] = 4,
	['5'] = 5,
	['6'] = 6,
	['7'] = 7,
	['8'] = 8,
	['9'] = 9,
	['a'] = 10,
	['b'] = 11,
	['c'] = 12,
	['d'] = 13,
	['e'] = 14,
	['f'] = 15
};

NSString *test_response = @"e319090673f858031e8167bb938d19133198acb4ff1ac60eb6d46aa4270902c2b7972d5f1c3039fae29b7d06971bbf7622204427fd2db37c0b59bd10b818254f05724c91580ec802c645e94e340358f621d4731f13f3a59dce81bbbc7437dae0ce81bbbc7437dae08931f9f60584502ff52cbe18f4d993571b18e0ea87d69778bdce3de17d7ba77fb6ba8c5f186314877dec496bd882c583bf215462dac62be47c6fa554f3df00c6ee8776e90311715271d97f03f954bd3f3a8a49613b9b608975f233b5df32912ba7a0fc12f71d2cc8178bab22f16945f74421b9d8fe5df43597d60e713ca35bdbb1903d707f03300e3074b60e1d1dc9c685813da6bb6c9a33b6812bce4a829f10d4b61d0b0c1ffd0317247e49ff5f18f8bd90df79acabf846434bfa185b53d0729fcdfad9ad212850306c35b07641f73cb44277d8a41a215fbd964fd8df4fe416514b6264ef17a20d67e2080a3ee1946411a0a3214e2f46b183424c4d085fb0ca7484de1a7f2bbcdff660d0b3b8f3f6a2292c0ba691b590738812b4e7aedc0f19ce677d38786d38aea2407439e76b56e3869dbe59c6e366c02fa5c42999123a323d89950b642ece01af38cd4cf10d3e034faebc20f041cd81da185ddec4ab1df7126b27caa8b5f65b72e5913ac1790477a307ab32be98774933521cdec6fd0359a6166ce6b256ab619eb2b6d1ba64d8904b2127419db6e8950771ce66738319b0ec38ed31ca20fce120be008238cd844e34fcf9465f50ee67797915367648645e0f0c18dd8f737c24b011b6bea6b653bc81cb840461a07f5a558a16800e8154ea4989860a7633b6d829f9533a6ccae3922f208582ca457c7365a43e9e65972edf76d3388a74c0a72202a51ccacac7fdd856b554f72d8678d48d70916beba15c0f3391df4d750597a87fd92def8ad5ec69d29d4340494528ca81d1d114f939bc9b3ed531f7e5b781afb6900aaed1751bd8ebc7449f9ec32f69069d275fac7efad7cd6910723861cc1e8fcc789bf57a8e5fb44277d8a41a215f49dcbceccb8125cf315af2964d5398ff069d275fac7efad7c2c8a468ffae5d1954396bfebbfb7a2a3b554ee9d4572bba12bd5d04d49b02a7279ce054b0242e9903078f728e99a305f64047d1c117a76a24530b1ff7b7393c01dfae6874d18c0965f79ce0280084491f2ff9cb680cfab0f64047d1c117a76a24530b1ff7b7393c01dfae6874d18c09c4971e9f07afb64632eb5bbd7b682e9ffec4010082c2f83536fef6dc742809d5672567141ceaa787790f2d186799badc72d8edba3fed26642cf589a68976fb79d5c9fb91409559da622c35a3e007b4e27add37d4a344a02ad9aafe3e9071e88a060528f0c9eefdd226d6cc07ec3090a0e401f03a52fbcdae68b0126cbf4a0ecc53c50e151e64c68e472f8517f802f0d809373878eebb6cd72ae20b0cb28b79503685cc1d85dc850a8c2247540caf7ccc70fbd3d04bf87dacaed68d972def27e7c7f4dded270e23d20870477cfb66835d1e2c38902ac94d49491c819abc58e3e80714081e5609e4a1abacca78a2e6500c1160e0bf3d248ec2ba9a37d4e9b6e28fa38c3b58bd2db629cf8160c5816bf96b66dbb7de80401e41012d3ab50b31afa89b0f0b23eab29ff313c6700e40d3fb2389e2940474588ede339b42fc32bc981b424f2d547419eebebfd2eafb66e6d7f097e0aef0dbf213376aa12f019cc33dd6ad51534dc16c2429d06223728d242fb6";

#define decryptionkey "721^26xE22776"

 int pandora_decrypt(const char *encrypted_text, char **out_buff, int *outsz)
{
	__block BLOWFISH_CTX bf_context;
	__block int bytes = 0;
	__block unsigned long l = 0;
	__block unsigned long r = 0;
	__block int location = 0;
	
	char *encryption_key = decryptionkey;
	int encrypted_len = (int)strlen(encrypted_text);
	void *decrypted_buf = calloc(sizeof(char) * encrypted_len + 1, 1);
	
	Blowfish_Init(&bf_context, (unsigned char *)encryption_key, (int)strlen(encryption_key));
	
	void (^handle_byte)(unsigned char) = ^void(unsigned char byte)
	{
		if (bytes++ < 4)
		{
			l = (l << 8) | byte;
		}
		else
		{
			r = (r << 8) | byte;
		}
		
		if (bytes >= 8)
		{
			Blowfish_Decrypt(&bf_context, &l, &r);
			for (int pass = 0; pass < 2; pass++)
			{
				for (int shift = 24; shift >= 0; shift -= 8)
				{
					unsigned char decbyte = (((pass == 0) ? l : r) >> shift) & 0xff;
					memcpy((decrypted_buf + location++), &decbyte, 1);
				}
			}
			
			bytes = 0;
			l = 0;
			r = 0;
		}
	};
	
	for (int pass = 0; pass < encrypted_len; pass += 2)
	{
		char transf_byte = h2i[encrypted_text[pass]];
		transf_byte *= 16;
		transf_byte +=  h2i[encrypted_text[pass + 1]];
		
		handle_byte(transf_byte);
	}
	
	while (bytes > 0)
	{
		handle_byte(0);
	}

	void *_out_buff = malloc(sizeof(char *) * ++location);
	snprintf(_out_buff, location, "%s", (char *)decrypted_buf);
	*outsz = location;
	*out_buff = _out_buff;
	free(decrypted_buf);
	
	return 0;
}

int pandora_encrypt(char *plaintext, char **out_buff, int *outsz)
{
	if (plaintext == NULL)
	{
		return -1;
	}
	
	int plaintext_len = (int)strlen(plaintext);

	
	__block BLOWFISH_CTX bf_context;
	__block int bytes = 0;
	__block unsigned long l = 0;
	__block unsigned long r = 0;
	__block int location = 0;
	
	char *encryption_key = decryptionkey;
	void *encrypted_buf = calloc(plaintext_len * sizeof(char *), 1);
	
	Blowfish_Init(&bf_context, (unsigned char *)encryption_key, (int)strlen(encryption_key));
	
	void (^handle_byte)(unsigned char) = ^void(unsigned char byte)
	{
		if (bytes++ < 4)
		{
			l = (l << 8) | byte;
		}
		else
		{
			r = (r << 8) | byte;
		}
		
		if (bytes >= 8)
		{
			Blowfish_Encrypt(&bf_context, &l, &r);
			for (int pass = 0; pass < 2; pass++)
			{
				for (int shift = 24; shift >= 0; shift -= 8)
				{
					unsigned char encbyte = (((pass == 0) ? l : r) >> shift) & 0xff;
					char bytes[2];
					bytes[1] = i2h[encbyte % 16];
					bytes[0] = i2h[encbyte / 16];
					memcpy((encrypted_buf + location), bytes, 2);
					location += 2;
				}
			}
			
			bytes = 0;
			l = 0;
			r = 0;
		}
	};

	for (int pass = 0; pass < plaintext_len; pass++)
	{
		handle_byte(plaintext[pass]);
	}
	
	while (bytes > 0)
	{
		handle_byte(0);
	}
	
	void *_out_buff = malloc(sizeof(char *) * ++location);
	snprintf(_out_buff, location, "%s", (char *)encrypted_buf);
	*outsz = location;
	*out_buff = _out_buff;
	free(encrypted_buf);
	
	return 0;
}

int main(int argc, const char * argv[])
{
	@autoreleasepool
	{
		char *decrypted = NULL;
		int dsize = 0;
		pandora_decrypt([test_response UTF8String], &decrypted, &dsize);
		
		char *encrypted = NULL;
		int esize = 0;
		pandora_encrypt(decrypted, &encrypted, &esize);
		
		NSLog(@"'%s'", decrypted);
		NSLog(@"%s", encrypted);
		assert(strncmp([test_response UTF8String], encrypted, esize) == 0);
		
		NSData *s =[[NSString stringWithFormat:@"%s", decrypted] dataUsingEncoding:NSUTF8StringEncoding];
		id json = [NSJSONSerialization JSONObjectWithData:s options:0 error:nil];
		NSLog(@"serialized %d objects", (int)[json count]);
		
		free(encrypted);
		free(decrypted);
	}

	return 0;
}
