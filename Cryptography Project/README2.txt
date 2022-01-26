Deniz Koc
Eylul Onar

In this phase the code will first reset SPK and OTK, then generate new spk and new 10 otk's. Identity Key is hardcoded.
You can directly run the code and re-generate spk, otks, server messages, kenc, khmac values etc. 
There is no hardcoded value other than identity key. Thats why at each run the key values will change.
Function generateKS() at line 115: generates session key
Function generateKDF() at line 127:  generates Key Derivation Function (KDF) Chain
Function decrypt() at line 146: checks the MAC values of the messages and decrypt them
Function explanations are given next to them.