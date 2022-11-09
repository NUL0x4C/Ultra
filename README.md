
<h2 align="center">Ultra: A Small Poc On An Encryption/Decryption Algorithm Used As A File Locker</h2>

<br>
<br>

## Why ?
- basically its an algorithm i though about to generate keys, using as much small code as possible 
- i wanted to see how ransomware function and run, so after studying leaked codes i figured i make something my own, and thus this repo

## support:
- encrypt/decrypt 1 file from the command line 
- encrypt/decrypt 1 direcotry from the command line


## Algorithm:
- it uses rc4 encryption algo to do the files encryption (with 20 bytes key)
- each file will have a different 20 byte encryption key generated for it using an hmac algorithm.
- the hmac algo takes 2 seeds, that will generate the key used for the decryption.
- changing these 2 seeds, will obviously change the key, and that's what is happening here.
- for the decryption part, the locker will save the seeds used in the file, and will save the first 4 bytes of the key used, so that we don't break the file if the key was mistakenly generated different.
- in case of large files, the locker read and write 65535 byte only and thats to save time.
- the locker uses `SetFilePointer` api with a negative lDistanceToMove and FILE_END parameters, so its reading files from the bottom up, and this exmplain the completley inversed offsets in the decryptor ...
- i tried reducing the code as much as i could, and not generating a big gap between large files encryption and other files algorithms (fully encrypted and partially encrypted) and thats too, to save time, so both situations have the same write function, which something you cant see in conti for example 
- both locker and decryptor, does checks to see if the given file is encrypted before running the algorithm again (and curropting it)
- the hmac algorithm is from [here](https://learn.microsoft.com/en-us/windows/win32/seccrypto/example-c-program--creating-an-hmac)
- conti locker leaked code that i studied can be found [here](https://github.com/Cracked5pider/conti_locker)

<br>
<br>


<p align="center">
    <img src="https://user-images.githubusercontent.com/111295429/200766206-f00b8db4-f863-4a35-a831-bddc1f60713e.png" alt="Ultra File">
</p>



