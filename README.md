# wordcompre
Secret math on text example to explore Seal

This program is meant as a demonstration of using the Integer Encoder with BFV scheme. It is not meant to take all cybersecurity precautions into consideration or meant to be the most efficient way.

The goal of this demonstration is to show how we can do secret math on text as such string -> char -> -> Unicode Number -> encode -> encrypted -> evaluate -> decrypt ->  decode -> Unicode Number -> char -> string.

The learning goal is to use the same word compare example for each encoder and scheme combination to achieve widest understanding of the Microsoft Seal library and ensure what is learned is consistent throughout the team.

It is encouraged to also explore levels, rotation, and serialization in each of the encoder and scheme combinations.

#Branches

IntEncBFV - This branch is for exploring the use of the integer encoder with the BFV scheme. This is what the first version of the word compare example was written for.

BatEncBFV - This branch is for exploring the use of the batch encoder with the BFV scheme.

CKKSEnc - This branch is for exploring the use of the CKKS encoder with the CKKS scheme.