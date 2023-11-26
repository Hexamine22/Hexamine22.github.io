#### EasyAssembly
 We are provided with a assembly source code file and a text file named flag.enc.txt. We can quickly compile the source code file and open it in IDA. 
 ```c++ 
int __cdecl main(int argc, const char **argv, const char **envp)
{
  _BYTE v4[26]; // [rsp+0h] [rbp-30h] BYREF
  char v5; // [rsp+1Bh] [rbp-15h]
  __int16 v6; // [rsp+1Ch] [rbp-14h]
  int i; // [rsp+2Ch] [rbp-4h]

  strcpy(v4, "Flag{xxxxxxxxx_xxx_xxxxxx}");
  v5 = 0;
  v6 = 0;
  for ( i = 0; i <= 26; ++i )
    printf("%d,", (unsigned int)((char)v4[i] * (char)v4[i]));
  return 0;
}
```

 The program is relatively simple: a loop takes each character from the string copied into flag, squares it, and then prints the result. The text file we have been provided has undergone the same operation, except for the fact that it had the flag inside the brackets, unlike the string in the main function. We can now quickly write a script to print the flag.
```python
import math

input_string = "4900,11664,9409,10609,15129,4225,13225,13225,10201,11881,9604,11664,14400,14641,9025,11025,14400,13225,9025,10201,9409,13225,14400,14641,1089,15625"

number_string = input_string.split(',')
characters = [chr(int(math.sqrt(int(num)))) for num in number_string]

flag = "".join(characters)
print(flag)
```
This script reverses the operation performed by calculating the square root of each number.
#### RAT
 We were provided with six text files, each containing decompiled .NET code. First, I looked at each of the dumps and labeled whatever I could make sense of. After this, I began with the function that I identified as the starting function. It decodes a string from base64 and then converts it to UTF-8. In the next line, we see that an instance of a class is created with a string. (I have renamed almost all the function names for clarity.)
 ```cs
 public static bool main()
		{
			bool result;
			try
			{
				main.jUHRpYhHETbLZM = Encoding.UTF8.GetString(Convert.FromBase64String(main.jUHRpYhHETbLZM));
				
				main.derive_key_func = new derive_key(main.jUHRpYhHETbLZM);
				
				main.zQMytbGsXGMq = main.derive_key_func.base64decode_callaes(main.zQMytbGsXGMq);
				main.kcsAnbQllNhK = main.derive_key_func.base64decode_callaes(main.kcsAnbQllNhK);
				main.etmOoKqzQSNWUc = main.derive_key_func.base64decode_callaes(main.etmOoKqzQSNWUc);
				main.ojnQySxLMWcv = main.derive_key_func.base64decode_callaes(main.ojnQySxLMWcv);
				main.AwrRHofWBj = main.derive_key_func.base64decode_callaes(main.AwrRHofWBj);
				main.AEvCmPszdgKM = main.derive_key_func.base64decode_callaes(main.AEvCmPszdgKM);
				main.CpcDUUwZCdbmtWbdar = main.derive_key_func.base64decode_callaes(main.CpcDUUwZCdbmtWbdar);
				main.hoBMwKCHhTn = main.derive_key_func.base64decode_callaes(main.hoBMwKCHhTn);
				main.lTnLbmaGlmbsZh = main.derive_key_func.base64decode_callaes(main.lTnLbmaGlmbsZh);
				main.xyUXNevkMJhe = main.derive_key_func.base64decode_callaes(main.xyUXNevkMJhe);
				main.OcnlieudLXTfku = sqfEwiihfq.QxLJMfHePB();
```
In the `derive_key` class, we observe that the provided string is utilized for key derivation through PBKDF2. The first argument serves as the password from which the key is derived, the second argument is used as the salt, and the third argument represents the number of iterations in the key derivation process. The first 32 derived bytes are used as the key to decrypt a string using AES, and the other 64 derived bytes are of no use to us as they are just used for some authentication in the AES function. 
```cs
	public class derive_key
	{
		// Token: 0x0600006F RID: 111 RVA: 0x000060EC File Offset: 0x000042EC
		public derive_key(string hNMViBcVNMrajll)
		{
			if (string.IsNullOrEmpty(hNMViBcVNMrajll))
			{
				throw new ArgumentException("masterKey can not be null or empty.");
			}
			using (Rfc2898DeriveBytes rfc2898DeriveBytes = new Rfc2898DeriveBytes(hNMViBcVNMrajll, uNalUFkOPUUKI.lHVJkjiscRk, 50000))
			{
				this.XYvxSDNanCoB = rfc2898DeriveBytes.GetBytes(32);
				this.XYfzCZIXMdkqv = rfc2898DeriveBytes.GetBytes(64);
			}
		}
    }
```
 
This byte array is used as the salt.
```cs
private static readonly byte[] lHVJkjiscRk = new byte[]
		{
			191,235,30,86,251,205,151,59,178,25,2,36,48,165,120,67,0,61,86,68,210,30,98,185,212,241,128,231,230,195,57,65
		};
```
Going further in the main function we see that strings are being decrypted.
``` cs
main.zQMytbGsXGMq = main.derive_key_func.base64decode_callaes(main.zQMytbGsXGMq);`
```
We can find the base64decode_callaes function in dump2. It first decodes the passed string from base64, then decrypts it using AES, and finally converts it to UTF-8.
```cs
public string base64decode_callaes(string zNVnoczrMDrz)
		{
			return Encoding.UTF8.GetString(this.AES(Convert.FromBase64String(zNVnoczrMDrz)));
		}
```
The AES decrypt function looks something like this 
```cs
public byte[] AES(byte[] JRYgSCBbuocg)
		{
			if (JRYgSCBbuocg == null)
			{
				throw new ArgumentNullException("input can not be null.");
			}
			byte[] result;
			using (MemoryStream memoryStream = new MemoryStream(JRYgSCBbuocg))
			{
				using (AesCryptoServiceProvider aesCryptoServiceProvider = new AesCryptoServiceProvider())
				{
					aesCryptoServiceProvider.KeySize = 256;
					aesCryptoServiceProvider.BlockSize = 128;
					aesCryptoServiceProvider.Mode = CipherMode.CBC;
					aesCryptoServiceProvider.Padding = PaddingMode.PKCS7;
					aesCryptoServiceProvider.Key = this.XYvxSDNanCoB;
					using (HMACSHA256 hmacsha = new HMACSHA256(this.XYfzCZIXMdkqv))
					{
						byte[] ncujqHRPQSXtFVA = hmacsha.ComputeHash(memoryStream.ToArray(), 32, memoryStream.ToArray().Length - 32);
						byte[] array = new byte[32];
						memoryStream.Read(array, 0, array.Length);
						if (!this.CtyhLNUaKAxkDP(ncujqHRPQSXtFVA, array))
						{
							throw new CryptographicException("Invalid message authentication code (MAC).");
						}
					}
					byte[] array2 = new byte[16];
					memoryStream.Read(array2, 0, 16);
					aesCryptoServiceProvider.IV = array2;
					using (CryptoStream cryptoStream = new CryptoStream(memoryStream, aesCryptoServiceProvider.CreateDecryptor(), CryptoStreamMode.Read))
					{
						byte[] array3 = new byte[memoryStream.Length - 16L + 1L];
						byte[] array4 = new byte[cryptoStream.Read(array3, 0, array3.Length)];
						Buffer.BlockCopy(array3, 0, array4, 0, array4.Length);
						result = array4;
					}
				}
			}
			return result;
		}
```
The key is set to the 32 bytes that were derived in the derive key class.
```cs
aesCryptoServiceProvider.Key = this.XYvxSDNanCoB;
```
IV is set to the first 16 bytes of the passed bytearray(the encrypted string that was decoded from base64)
```cs
using (MemoryStream memoryStream = new MemoryStream(JRYgSCBbuocg)
......
byte[] array2 = new byte[16];
memoryStream.Read(array2, 0, 16);
aesCryptoServiceProvider.IV = array2;
```
dump1.txt shows all the strings.
```cs
public static string zQMytbGsXGMq = "BY9Al1NVyus/1Jx0H52UHAmHnTl+XCgWqH8VNcLTDWTnMbMob5alm5ZpEDjzuCs3us+C2NRPmR9bJbXUFCqmvQ==";

public static string kcsAnbQllNhK = "hFc4AR0EIFR9+mcXqCxdkWjoEkMWemLJ+3DcgLk2Ykei7nLTWzJueAOaI8rxSaNm297FtiishjnOM4b0BcaMrzqq72QpLGITg2XfEHBuP3U=";

public static string etmOoKqzQSNWUc = "DiNxi2kxlyGzToMWFVHEDFad6SHRDIaxsZ8CdeQVNCICvAkAb9MBV5xjFxnTocFp/tCdRj2+nU4V+72ntobvSnkLY2VPx40Ru9cHL5pQADQ=";

public static string ojnQySxLMWcv = "vN8GhxWNvk/e1L1Ra5v4gbYeyvCV6ycB2YXr8ei5YCT4yrBFIxBJyZfDEHkKLSrCh8WBsOPtS2e/VNXHS8axbA==";

public static string FagpIelPihMeZgv = "%AppData%";

public static string pqWVuilwKDz = "";
		
public static string jUHRpYhHETbLZM = "emFVd1BMcnk5amFrQUxyYVQzRFUxN0Z6Q015SlZ5S0g=";

public static string AwrRHofWBj = "crCqySGjzlNjZ1CkRhRNcuDaWZIMCNPbasZF7feiHbkMGaT10+mqbP38rU4zcOBuTyHz3Ab6l+V071XuP++dHDWYXkgJZdKDsWoBd0WJ0sY=";
```
We can write a script to decrypt each string one by one.
```python
from hashlib import pbkdf2_hmac
from base64 import b64decode
from Crypto.Cipher import AES



encrypted_data= b64decode(
    'crCqySGjzlNjZ1CkRhRNcuDaWZIMCNPbasZF7feiHbkMGaT10+mqbP38rU4zcOBuTyHz3Ab6l+V071XuP++dHDWYXkgJZdKDsWoBd0WJ0sY=') //replace with whatever string you want to decrypt

salt = bytes([191, 235, 30, 86, 251, 205, 151, 59, 178, 25, 2, 36, 48, 165, 120, 67, 0, 61, 86, 68, 210, 30, 98, 185, 212, 241, 128, 231, 230, 195, 57, 65])

first_key = b64decode('emFVd1BMcnk5amFrQUxyYVQzRFUxN0Z6Q015SlZ5S0g=')
 
key = pbkdf2_hmac('sha1', first_key, salt, 50000, 32)

flag = encrypted_data[16:]
iv = encrypted_data[:16]

cipher = AES.new(key, AES.MODE_CBC, iv)
decrypted_data = cipher.decrypt(encrypted_data)

print('output:', decrypted_data.decode('utf-8', errors='ignore'))

```
You'll get the flag after decrypting each encrypted config string using the script above.

#### Passcode
 We have been provided with an ELF binary. The main function shows that it takes two 4-byte integers as input, then passes them to a function along with what appears to be a key. Following this, it compares the input with some hardcoded values and prints 'Access Granted' if they match.
 ```C++
 __int64 __fastcall main(int a1, char **a2, char **a3)
{
  int key[6]; // [rsp+0h] [rbp-20h] BYREF
  __int32 input[2]; // [rsp+18h] [rbp-8h] BYREF

  input[0] = 0;
  input[1] = 0;
  printf("Enter Passcode 1 (Only 8 decimal numbers)):");
  __isoc99_scanf("%d", input);
  printf("Enter Passcode 2 (Only 8 decimal numbers):");
  __isoc99_scanf("%d", &input[1]);
  key[0] = 0xBC614E;
  key[1] = 0x5397FB1;
  key[2] = 0x165EC15;
  key[3] = 0x5E30A78;
  xtea_encrypt((unsigned int *)input, (__int64)key);
  if ( input[0] == 0xBC2A7453 && input[1] == 0xF13A2B3E )
    printf("Correct!, Access Granted.");
  else
    printf("Try Again.");
  return 0LL;
}
```
Looking into the function called we observe calculations being performed on the provided input. I used the Capa Explorer plugin in IDA Pro to identify the algorithm. Capa identifies this function as 'encrypt data using XTEA'. XTEA is a symmetric encryption algorithm that typically employs a 128-bit key and operates on blocks of 8 bytes.
```C++
__int64 __fastcall xtea_encrypt(unsigned int *ptr_to_input, __int32 *key)
{
  __int64 result; // rax
  unsigned int i; // [rsp+20h] [rbp-10h]
  unsigned int sum; // [rsp+24h] [rbp-Ch]
  unsigned int second_number; // [rsp+28h] [rbp-8h]
  unsigned int first_number; // [rsp+2Ch] [rbp-4h]

  first_number = *ptr_to_input;
  second_number = ptr_to_input[1];
  sum = 0;
  for ( i = 0; i <= 0x1F; ++i )
  {
    first_number += (((second_number >> 5) ^ (0x10 * second_number)) + second_number) ^ (key[sum & 3] + sum);
    sum -= ~0x9E3779B8;
    second_number += (((first_number >> 5) ^ (0x10 * first_number)) + first_number) ^ (key[(sum >> 11) & 3] + sum);
  }
  *ptr_to_input = first_number;
  result = second_number;
  ptr_to_input[1] = second_number;
  return result;
}
```
Given that we have both the key and the encrypted data (hardcoded values: 0xBC2A7453 and 0xF13A2B3E), we can write a script to decrypt these values using XTEA. After that we can use the decrypted values as our input to pass this `if ( input[0] == 0xBC2A7453 && input[1] == 0xF13A2B3E )` check.

The main differences between XTEA decryption and encryption are as follows: XTEA encryption initializes 'sum' at 0, incrementing it in each round, while decryption starts 'sum' with a value used in the last encryption round. Encryption involves bitwise operations and additions, while decryption reverses these operations with subtractions and inverse bitwise operations.

You can use the following script to get the flag. I have included the xtea_encrypt function, even though it's not being used here.

```C++
#include <stdio.h>
#include <stdint.h>

void xtea_encrypt(uint32_t v[2], const uint32_t key[4]);
void xtea_decrypt(uint32_t v[2], const uint32_t key[4]);

int main() {
    uint32_t encrypted_numbers[2] = {0xBC2A7453 , 0xF13A2B3E}; //What our input should encrypt to
    uint32_t key[4] = {0xBC614E, 0x5397FB1, 0x165EC15, 0x5E30A78}; //The key
    xtea_decrypt(encrypted_numbers, key);
    uint32_t num[2] = {encrypted_numbers[0],encrypted_numbers[1]}; 
    printf("Numbers found, Num 1 = %d and Num 2 = %d", num[0],num[1]);
    return 1;
}
void xtea_encrypt(uint32_t input[2], const uint32_t key[4]) {
    uint32_t delta = 0x9e3779b9;
    uint32_t sum = 0;

    for (int round = 0; round < 32; ++round) {
        input[0] += (((input[1] << 4) ^ (input[1] >> 5)) + input[1]) ^ (sum + key[sum & 3]);
        sum += delta;
        input[1] += (((input[0] << 4) ^ (input[0] >> 5)) + input[0]) ^ (key[(sum >> 11) & 3] + sum);
        
    }
}
void xtea_decrypt(uint32_t input[2], const uint32_t key[4]) {
    uint32_t delta = 0x9e3779b9;
    uint32_t sum = delta * 32; // Start with the sum used in the last encryption round

    for (int round = 0; round < 32; ++round) {
        input[1] -= (((input[0] >> 5) ^ (input[0] << 4)) + input[0]) ^ (key[(sum >> 11) & 3] + sum);
        sum -= delta;
        input[0] -= (((input[1] >> 5) ^ (input[1] << 4) ) + input[1]) ^ (sum + key[sum & 3]);
    }
}
```
Checking the output of this function
```
Enter Passcode 1 (Only 8 decimal numbers)):77654779
Enter Passcode 2 (Only 8 decimal numbers):96541165
Correct!, Access Granted
```

 










 
 

 