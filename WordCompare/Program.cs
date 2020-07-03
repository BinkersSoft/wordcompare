using System;
using System.IO;
using Microsoft.Research.SEAL;

namespace WordCompare
{
    class Program
    {
        /*
        This program is meant as a demonstration of using the Integer Encoder with BFV scheme.
        It is not meant to take all cybersecurity precautions into consideration or meant
        to be the most efficient way.

        The goal of this demonstration is to show how we can do secret math on text as such
        string -> char -> -> Unicode Number -> encode -> encrypted -> evaluate -> decrypt ->
        decode -> Unicode Number -> char -> string.
        */

        static void Main()
        {
            //Load source data to be searched.
            string[] sourceData = File.ReadAllLines("words_alpha.txt");
            Console.WriteLine("Loaded source data.");

            //Load data to used in search. This current example works with searching one word
            string[] searchData = File.ReadAllLines("searchOneWord.txt");
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
            int wordLength = 15; //Currently, all words must be below a certain length
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
                byte[][] sourceCharacterArray = new byte[wordLength][];
                for (int j = 0; j < sourceWordCount; j++)
                {
                    using Plaintext arrayInitPlaintext = encoder.Encode(0); //Filling the data with 0's
                    using Ciphertext arrayInitEncrypted = new Ciphertext();
                    encryptor.Encrypt(arrayInitPlaintext, arrayInitEncrypted);
                    arrayInitEncrypted.Save(encryptedStream, ComprModeType.Deflate);

                    sourceCharacterArray[j] = encryptedStream.ToArray(); //Save the data as bytes.

                    encryptedStream.Seek(0, SeekOrigin.Begin); //Move the pointer back to the beginning of the stream

                }

                sourceEncryptedArray[i] = sourceCharacterArray;
            }

            encryptedStream.Seek(0, SeekOrigin.Begin);

            byte[][][] searchEncryptedArray = new byte[searchData.Length][][];
            for (int i = 0; i < searchData.Length; i++)
            {
                byte[][] searchCharacterArray = new byte[wordLength][];
                for (int j = 0; j < sourceWordCount; j++)
                {
                    using Plaintext arrayInitPlaintext = encoder.Encode(0); //Filling the data with 0's
                    using Ciphertext arrayInitEncrypted = new Ciphertext();
                    encryptor.Encrypt(arrayInitPlaintext, arrayInitEncrypted);
                    arrayInitEncrypted.Save(encryptedStream, ComprModeType.Deflate);

                    searchCharacterArray[j] = encryptedStream.ToArray(); //Save the data as bytes.

                    encryptedStream.Seek(0, SeekOrigin.Begin); //Move the pointer back to the beginning of the stream
                }
                searchEncryptedArray[i] = searchCharacterArray;
            }

            encryptedStream.Seek(0, SeekOrigin.Begin);

            //Cycle through all strings in sourceData, up to sourceWordCount.
            for (int i = 0; i < sourceWordCount; i++)
            {
                //Create char array for all char in source.Data[i].
                char[] charArray = sourceData[i].ToCharArray();

                Console.Write("Source Words being encrypted: ");
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

                    //Print to console to validate values, for testing only.
                    using Plaintext plainData = new Plaintext();
                    decryptor.Decrypt(charEncrypted, plainData);
                    long dataVal = encoder.DecodeInt64(plainData);
                    Console.Write(dataVal + " ");

                    sourceEncryptedArray[i][j] = encryptedStream.ToArray();
                    encryptedStream.Seek(0, SeekOrigin.Begin); //Move the pointer back to the beginning of the stream

                }

                Console.WriteLine();

            }
            Console.WriteLine();
            encryptedStream.Seek(0, SeekOrigin.Begin);

            for (int i = 0; i < searchData.Length; i++)
            {
                char[] charArray = searchData[i].ToCharArray();
                Console.Write("Search Word being encrypted: ");

                for (int j = 0; j < charArray.Length; j++)
                {
                    //Convert charArrayTemp[c] to Int64.
                    long charInt64 = Convert.ToInt64(charArray[j]);

                    //Encode integer into plaintext elements.
                    using Plaintext charPlaintext = encoder.Encode(charInt64);

                    //Encrypt the plaintext.
                    encryptor.Encrypt(charPlaintext, charEncrypted);

                    charEncrypted.Save(encryptedStream, ComprModeType.Deflate);

                    //Print to console to validate values, for testing only.
                    using Plaintext plainData = new Plaintext();
                    decryptor.Decrypt(charEncrypted, plainData);
                    long dataVal;
                    dataVal = encoder.DecodeInt64(plainData);
                    Console.Write(dataVal + " ");

                    searchEncryptedArray[i][j] = encryptedStream.ToArray();
                    encryptedStream.Seek(0, SeekOrigin.Begin); //Move the pointer back to the beginning of the stream
                }
                Console.WriteLine();
            }

            Console.WriteLine();
            encryptedStream.Seek(0, SeekOrigin.Begin);

            //Send data out to be analyzed

            byte[][][] resultArray = new byte[sourceEncryptedArray.Length][][];

            for (int i = 0; i < sourceEncryptedArray.Length; i++)
            {
                byte[][] resultWordArray = new byte[15][];
                Console.Write("Word being decrypted: ");
                for (int j = 0; j < sourceEncryptedArray[i].Length; j++)
                {
                    MemoryStream sourceEncryptedStream = new MemoryStream(sourceEncryptedArray[i][j]);
                    MemoryStream searchEncryptedStream = new MemoryStream(searchEncryptedArray[0][j]); //We are using 0 instead of i because we are only looping through one word.

                    sourceDataEncrypted.Load(context, sourceEncryptedStream);
                    searchDataEncrypted.Load(context, searchEncryptedStream);

                    //Print to console to validate values, for testing only.
                    decryptor.Decrypt(sourceDataEncrypted, plainResult);
                    resultTest = encoder.DecodeInt64(plainResult);
                    Console.Write(resultTest + " ");

                    evaluator.Negate(sourceDataEncrypted, encryptedResult);
                    evaluator.AddInplace(encryptedResult, searchDataEncrypted);

                    encryptedResult.Save(encryptedStream, ComprModeType.Deflate);
                    resultWordArray[j] = encryptedStream.ToArray();

                    encryptedStream.Seek(0, SeekOrigin.Begin);

                }
                resultArray[i] = resultWordArray;

                Console.WriteLine();

            }

            Console.WriteLine();

            //This 2D loop looks at our resultArray array, read the bytes into a MemoryStream to be decrypted and decoded, then print the values of each character.
            for (int i = 0; i < resultArray.Length; i++)
            {
                Console.Write("Word Results: ");
                for (int j = 0; j < resultArray[i].Length; j++)
                {
                    MemoryStream resultsEncryptedStream = new MemoryStream(resultArray[i][j]);
                    using Ciphertext results = new Ciphertext();
                    results.Load(context, resultsEncryptedStream);


                    decryptor.Decrypt(results, plainResult);
                    compareResult = encoder.DecodeInt32(plainResult);
                    Console.Write(compareResult + " ");
                }
                Console.WriteLine();
            }
        }

    }

}
