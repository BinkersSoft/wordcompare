﻿using System;
using System.IO;
using Microsoft.Research.SEAL;

namespace WordCompare
{
    class Program
    {

        static void Main()
        {

            //OrigionalExample();
            MikeSCode.BatchEncoderExample();
        }

        /*
        This program is meant as a demonstration of using the Integer Encoder with BFV scheme.
        It is not meant to take all cybersecurity precautions into consideration or meant
        to be the most efficient way.

        The goal of this demonstration is to show how we can do secret math on text as such
        string -> char -> -> Unicode Number -> encode -> encrypted -> evaluate -> decrypt ->
        decode -> Unicode Number -> char -> string.
        */
        public static void OrigionalExample()
        {
            //Load source data to be searched.
            string[] sourceData = File.ReadAllLines("words_alpha.txt");
            Console.WriteLine("Loaded source data.");

            //Load data to used in search.
            string[] searchData = File.ReadAllLines("search.txt");
            Console.WriteLine("Loaded search data.");

            /*
            The setup code is taken directly from SEALNet Examples Integer Encoder for BFV
            and I do not understand them enough to make them optimal values.
            */
            using EncryptionParameters parms = new EncryptionParameters(SchemeType.BFV);
            ulong polyModulusDegree = 4096;
            parms.PolyModulusDegree = polyModulusDegree;
            parms.CoeffModulus = CoeffModulus.BFVDefault(polyModulusDegree);
            parms.PlainModulus = new Modulus(512);
            using SEALContext context = new SEALContext(parms);
            using KeyGenerator keygen = new KeyGenerator(context);
            using PublicKey publicKey = keygen.PublicKey;
            using SecretKey secretKey = keygen.SecretKey;
            using Encryptor encryptor = new Encryptor(context, publicKey);
            using Evaluator evaluator = new Evaluator(context);
            using Decryptor decryptor = new Decryptor(context, secretKey);
            using IntegerEncoder encoder = new IntegerEncoder(context);

            //Declare encrypted variables that cannot be recycled.
            int sourceWordCount = 15;
            int compareResult = 1;
            long resultTest = 1;
            using Ciphertext sourceDataEncrypted = new Ciphertext();
            using Ciphertext searchDataEncrypted = new Ciphertext();
            using Ciphertext charEncrypted = new Ciphertext();
            using Ciphertext encryptedResult = new Ciphertext();
            using Plaintext plainResult = new Plaintext();
            MemoryStream encryptedStream = new MemoryStream();


            Console.WriteLine("Initializing arrays.");

            /*
            Initializing source and search byte[][][] arrays so we can hold ciphertexts
            as streams.
            */
            byte[][][] sourceEncryptedArray = new byte[15][][];
            for (int i = 0; i < sourceWordCount; i++)
            {
                byte[][] sourceCharacterArray = new byte[15][];
                for (int j = 0; j < sourceWordCount; j++)
                {
                    using Plaintext arrayInitPlaintext = encoder.Encode(j);
                    using Ciphertext arrayInitEncrypted = new Ciphertext();
                    encryptor.Encrypt(arrayInitPlaintext, arrayInitEncrypted);
                    arrayInitEncrypted.Save(encryptedStream, ComprModeType.Deflate);
                    sourceCharacterArray[j] = encryptedStream.ToArray();

                }

                sourceEncryptedArray[i] = sourceCharacterArray;
            }

            byte[][][] searchEncryptedArray = new byte[searchData.Length][][];
            for (int i = 0; i < searchData.Length; i++)
            {
                byte[][] searchCharacterArray = new byte[searchData.Length][];
                for (int j = 0; j < searchData.Length; j++)
                {
                    using Plaintext arrayInitPlaintext = encoder.Encode(j);
                    using Ciphertext arrayInitEncrypted = new Ciphertext();
                    encryptor.Encrypt(arrayInitPlaintext, arrayInitEncrypted);
                    arrayInitEncrypted.Save(encryptedStream, ComprModeType.Deflate);
                    searchCharacterArray[j] = encryptedStream.ToArray();

                }

                searchEncryptedArray[i] = searchCharacterArray;
            }

            //Cycle through all strings in sourceData, up to sourceWordCount.
            for (int i = 0; i < sourceWordCount; i++)
            {

                //Create char array for all char in source.Data[i].
                char[] charArray = sourceData[i].ToCharArray();

                //Cycle through each character.
                for (int j = 0; j < charArray.Length; j++)
                {

                    //Convert charArrayTemp[c] to Int64.
                    long charInt64 = Convert.ToInt64(charArray[j]);

                    //Encode integer into plaintext elements.
                    using Plaintext charPlaintext = encoder.Encode(charInt64);

                    //Encrypt the plaintext.
                    encryptor.Encrypt(charPlaintext, charEncrypted);

                    charEncrypted.Save(encryptedStream, ComprModeType.Deflate);

                    sourceEncryptedArray[i][j] = encryptedStream.ToArray();

                }

            }

            //Send data out to be analyzed

            //Initialize resultArray[][], may need to epand to resultArray[][][].
            byte[][] resultArray = new byte[sourceEncryptedArray.Length][];

            for (int i = 0; i < sourceEncryptedArray.Length; i++)
            {

                for (int j = 0; j < sourceEncryptedArray[i].Length; j++)
                {
                    //Restore byte[] to MemoryStream.
                    MemoryStream sourceEncryptedStream = new MemoryStream(sourceEncryptedArray[i][j]);
                    //MemoryStream searchEncryptedStream = new MemoryStream(searchEncryptedArray[i][j]);

                    //Load MemoryStream to Ciphertext
                    sourceDataEncrypted.Load(context, sourceEncryptedStream);
                    //searchDataEncrypted.Load(context, searchEncryptedStream);

                    //Print to console to validate values, for testing only.
                    decryptor.Decrypt(sourceDataEncrypted, plainResult);
                    resultTest = encoder.DecodeInt64(plainResult);
                    Console.WriteLine("Decrypted sourceDataEncrypted = " + resultTest);
                    //decryptor.Decrypt(searchDataEncrypted, plainResult);
                    //resultTest = encoder.DecodeInt64(plainResult);
                    //Console.WriteLine("Decrypted searchDataEncrypted = " + resultTest);

                    //evaluator.Negate(sourceDataEncrypted, encryptedResult);
                    //This is where all goes wrong..... and I can't figure out why.
                    //evaluator.AddInplace(encryptedResult, searchDataEncrypted);

                    encryptedResult.Save(encryptedStream, ComprModeType.Deflate);

                    resultArray[i] = encryptedStream.ToArray();
                }

            }

            for (int i = 0; i < resultArray.Length; i++)
            {
                decryptor.Decrypt(encryptedResult, plainResult);
                compareResult = encoder.DecodeInt32(plainResult);
                Console.WriteLine(compareResult);
            }
        }

    }

}
