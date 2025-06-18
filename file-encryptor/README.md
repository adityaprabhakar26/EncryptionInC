Roughly going to explain fse/fsd.

So fse is encrypting, fsd is decrypting.
basically, you say if you want to encrypt or decrypt some "infile" and set some "outfile" then enter a key.

so if you read the arcfour stuff, the concept is that even with the wrong key, you still get output, it'll just be garbage and completely inaccurate. so when you enter your key, if it is wrong, you still get a outfile, it'll just be useless. but one cool thing about this is we will make it so that if you enter the wrong key, you wont get all that garabge, just a error saying its the wrong key.

it's hard to implement this, so this is the basic thought process. imagine you have some plain text, and want to encrypt into some cipher text. and now someone wants to decrypt it, so they need our key to do that. first few ideas would be, lets put the key at the start and separate it from the encrypted part(obviously not secure because an adversary can just read it and decrypt themselves). Another idea may be encrypt the key and put it at the start. still not the most secure because, by constraint of our 2048 bits, the adversary can still know that the key will be within that first 2048 bits, so thats information they can use to find a pattern or whatever to go backwards on. so also not secure.

so a better idea is a hash on the key to a bunch of bits. so even if the adversary obtains this string of bits, they can't do anything with it because a hash is one way(unless the adversary tries a bunch of different passwords and compares the hash of theirs to this hash until they find the right one but thats pure luck i think).

but once again, this seems secure but we can do better because with that solution, we are still giving away important information that may be used somehow.

hashing is on the right track, but we need to find where to store the hash each time. so thats where securerand comes in, it is basically generating a 16 bit unsigned integer(0 to ~65000), randomly and cryptographically secure. we also then create padding of 0- ~650000 BYTES of random data. so the offset, then the padding. then we can put our hash.
and then the data. and then we encrypt everything.

to decrypt, we first decrypt the offset(first 2 bites/16 bits of the file) using our key. if its the correct key, we get the correct offset value, otherwise, we get some random integer from 0 to ~65k. so if its the wrong key, then it reads a wrong hash(because it believes the offset is further or higher than it actually is), so then we can say its the wrong key entered.
