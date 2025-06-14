here's a link to the wikipedia article on the stream cipher we will be using.
https://en.wikipedia.org/wiki/RC4

RC4 is a pretty simple stream cipher and was used a lot, but now considered not secure. A way to make it "secure"(enough for our purposes of learning how to build an encryption library from scratch + being able to encrypt files with it) is to have a massive key(randomized too) and also dispose of a lot of the initial output bytes.

Here is a simple explanation of the cipher:

We take an array, S, of length 256(for simpler purposes we can make this a smaller value, we just need to make sure this change in length is reflected everywhere, including the mod 256s), where the values are equal to its index.
For S[0] = 0 ... S[255] = 255
Then we take some key, encode it(ASCII)
Then we use a key array, T, of length 256.
The inputs of this array are the encoding of the key, repated till the array is filled. For example if key = "HELLO", it would be encoded as
72 69 76 76 79. So T[0] = 72, T[1] = 69 ... T[4] = 79, T[5] = 72 ... T[255] = 72

Now comes Key Scheduling,
j = 0
for i = 0 to 255:
j = (j + S[i] + T[i]) mod 256
swap S[i] and S[j]
end;

This basically uses our key to scramble up our S array depending on values of our Key. The idea here is that if we don't scramble up S depending on our Key, then our pseudo random algorithm would generate the same keystream for every key. So, we scramble our S using our key so that when it comes to the stream generation, we get a unique key stream.

and our Pseudo Random Algo(Stream Generation),
i = j = 0
for i = i + 1 to length of Plain Text
j = (j + S[i]) mod 256
swap S[i] and S[j]
t = (S[i] + S[j]) mod 256
KeyStream = S[t]
end;

Generates our Key Stream. The point of the keystream is to mock a One-Time Pad. The problem with One-Time Pads, which basically takes a key that is as long as your message and then does XOR on each bit of the message and key, is that you need a key as long as your message which is pretty impractical. The way stream ciphers like RC4 combat this is by taking a shorter key and generating a keystream of the messages length with our pseudo random algorithm.

For Encryption / Decryption we use our KeyStream and xor(exclusive or)
So we convert the plain text and keystream to binary and then xor by the bits.
Cipher Text = Plain Text xor KeyStream
Plain Text = Cipher Text xor KeyStream
For example to encrypt, let our plain text be PT, and the output cipher text is CT.
If PT = [6], KeyStream = [1],
in binary, PT = 0110, KeySteam = 0001, so by the bits, we would get CT = 0111, which is 7 in decimal.
