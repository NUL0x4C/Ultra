### Ultra: A Small Poc On An Encryption/Decryption Algorithm Used As A File Locker





```
    			FULL ENCRYPTION									   PARTIAL ENCRYPTION
	-----------------------------						-----------------------------
	|							|						|							|
	|							|						|							|
	|							|						|	      RAW DATA	        |
	|		                    |						|							|
	|							|						|							|
	|							|						|							|
	|         ENC DATA			|					    -----------------------------
	|							|                       |							|
	|							|                       |							|
	|							|                       |	 65535 BYTE ENC DATA    |
	|							|                       |							|
	|							|                       |							|
	-----------------------------                       -----------------------------
	|	4 BYTE ECRYPTION TYPE   |						|	4 BYTE ECRYPTION TYPE   |
	|	   [0xB2B2B2B2]			|						|		[0xA1A1A1A1]		|
	-----------------------------						-----------------------------
	|  4 BYTE PART OF THE KEY	|						|  4 BYTE PART OF THE KEY	|
	-----------------------------						-----------------------------
	|							|						|							|
	|	  15 BYTE [SEEDS]		|						|	   15 BYTE [SEEDS]		|
	|							|						|							|
	|							|						|							|
	-----------------------------						-----------------------------

```
