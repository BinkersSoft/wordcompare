using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using Microsoft.Research.SEAL;

namespace WordCompare
{
    class MikeSCode
    {
        public static void BatchEncoderExample()
        {
            //Path to the files
            string wordsPath = "words_alpha100.txt";
            string searchPath = "searchOneWord.txt"; //This example can only work with one word

            if (File.Exists(wordsPath) && File.Exists(searchPath))
            {

                //Arrays of all the words in the search.txt and words.txt files
                string[] wordList = File.ReadAllLines(wordsPath);
                string[] searchList = File.ReadAllLines(searchPath);

                List<List<ulong>> wordListToHexNumData = new List<List<ulong>>();
                List<List<ulong>> searchListToHexNumData = new List<List<ulong>>();

                //a foreach loop for each file. It converts a word into HEX(which also represents unicode), then into it's integer value
                foreach (var word in wordList)
                {
                    wordListToHexNumData.Add(word.Select(t => (ulong)Convert.ToInt32($"{Convert.ToUInt16(t):X4}", 16)).ToList());
                }

                foreach (var word in searchList)
                {
                    searchListToHexNumData.Add(word.Select(t => (ulong)Convert.ToInt32($"{Convert.ToUInt16(t):X4}", 16)).ToList());
                }

                //Debugging purpose - Lets us print the values in our 2D uLong List
                //foreach (var element in searchListToHexNumData)
                //{
                //    foreach (var item in element)
                //    {
                //        Console.WriteLine(item);
                //    }
                //    Console.WriteLine();
                //}



                //Parameters
                using EncryptionParameters parms = new EncryptionParameters(SchemeType.BFV);
                ulong polyModulusDegree = 8192;
                parms.PolyModulusDegree = polyModulusDegree;
                parms.CoeffModulus = CoeffModulus.BFVDefault(polyModulusDegree);
                parms.PlainModulus = PlainModulus.Batching(polyModulusDegree, 20);
                using SEALContext context = new SEALContext(parms);

                using var qualifiers = context.FirstContextData.Qualifiers;
                Console.WriteLine($"Batching enabled: {qualifiers.UsingBatching}");

                //Keys
                using KeyGenerator keygen = new KeyGenerator(context);
                using PublicKey publicKey = keygen.PublicKey;
                using SecretKey secretKey = keygen.SecretKey;
                using RelinKeys relinKeys = keygen.RelinKeysLocal();
                using Encryptor encryptor = new Encryptor(context, publicKey);
                using Evaluator evaluator = new Evaluator(context);
                using Decryptor decryptor = new Decryptor(context, secretKey);

                //Using Batch encoder
                using BatchEncoder encoder = new BatchEncoder(context);

                ulong slotCount = encoder.SlotCount;
                ulong rowSize = slotCount / 2;

                MemoryStream encryptedWordsStream = new MemoryStream();
                MemoryStream encryptedSearchStream = new MemoryStream();

                //Words Data - encoding and encrypting data and saving it into the encryptedWordsStream MemoryStream
                foreach (var word in wordListToHexNumData)
                {
                    using Plaintext plainData = new Plaintext();
                    encoder.Encode(word, plainData);

                    using Ciphertext encryptedData = new Ciphertext();
                    encryptor.Encrypt(plainData, encryptedData);

                    encryptedData.Save(encryptedWordsStream);
                }

                //Move pointer of encryptedWordsStream back to the beginning
                encryptedWordsStream.Seek(0, SeekOrigin.Begin);

                //Debugging purpose - Prints information on the memory stream. Used to to check the current pointers position
                //Console.WriteLine(
                //"encryptedWordsStream: Capacity = {0}, Length = {1}, Position = {2}\n",
                //    encryptedWordsStream.Capacity.ToString(),
                //    encryptedWordsStream.Length.ToString(),
                //    encryptedWordsStream.Position.ToString());

                //Search Data - encoding and encrypting data and saving it into the encryptedSearchStream MemoryStream
                foreach (var word in searchListToHexNumData)
                {
                    using Plaintext plainData = new Plaintext();
                    encoder.Encode(word, plainData);
                    using Ciphertext encryptedData = new Ciphertext();
                    encryptor.Encrypt(plainData, encryptedData);
                    encryptedData.Save(encryptedSearchStream);

                    //Debugging purpose - Used to check the values inside the encrypted data
                    //List<ulong> arrayPrintOut = new List<ulong>();

                    //using Plaintext plainPrintOut = new Plaintext();
                    //decryptor.Decrypt(encryptedData, plainPrintOut);
                    //encoder.Decode(plainPrintOut, arrayPrintOut);

                    //foreach (var item in arrayPrintOut)
                    //{
                    //    if(item != 0)
                    //    {
                    //        Console.Write(item + " ");
                    //    }
                    //}
                    //Console.WriteLine();
                }

                //Move pointer of encryptedSearchStream back to the beginning
                encryptedSearchStream.Seek(0, SeekOrigin.Begin);

                //Debugging purpose - Prints information on the memory stream. Used to to check the current pointers position
                //Console.WriteLine(
                //"encryptedSearchStream: Capacity = {0}, Length = {1}, Position = {2}\n",
                //    encryptedSearchStream.Capacity.ToString(),
                //    encryptedSearchStream.Length.ToString(),
                //    encryptedSearchStream.Position.ToString());


                using Ciphertext sourceDataEncrypted = new Ciphertext();
                using Ciphertext searchDataEncrypted = new Ciphertext();
                using Ciphertext encryptedResult = new Ciphertext();

                searchDataEncrypted.Load(context, encryptedSearchStream);
                MemoryStream encryptedStream = new MemoryStream();

                //While loop that loads the next set of data until the position of the pointer is at the end.
                while (encryptedWordsStream.Length > encryptedWordsStream.Position)
                {
                    //Load the steam into sourceDataEncrypted CipherText
                    sourceDataEncrypted.Load(context, encryptedWordsStream);

                    //Debugging purpose - decrypt and decode the data, making sure the data is correct/expected
                    //List<ulong> finalResultArray = new List<ulong>();

                    //using Plaintext plainDataResult = new Plaintext();
                    //decryptor.Decrypt(sourceDataEncrypted, plainDataResult);
                    //encoder.Decode(plainDataResult, finalResultArray);

                    //foreach (var item in finalResultArray)
                    //{
                    //    if (item != 0)
                    //    {
                    //        Console.Write($"%u{Convert.ToUInt16(item):X4}" + " ");
                    //    }
                    //}

                    //Console.WriteLine();

                    //This will take our data of our Search word and subtract it to the current word in the stream
                    evaluator.Negate(sourceDataEncrypted, encryptedResult);
                    evaluator.AddInplace(encryptedResult, searchDataEncrypted);

                    //Save the result in the new Stream
                    encryptedResult.Save(encryptedStream);

                }

                //Put the pointer back to 0
                encryptedStream.Seek(0, SeekOrigin.Begin);

                //Debugging purpose - Prints information on the memory stream. Used to to check the current pointers position
                Console.WriteLine(
                "encryptedStream: Capacity = {0}, Length = {1}, Position = {2}\n",
                    encryptedStream.Capacity.ToString(),
                    encryptedStream.Length.ToString(),
                    encryptedStream.Position.ToString());


                using Ciphertext sourceResultEncrypted = new Ciphertext();

                int counter = 1;

                //While loop that loads the next set of data until the position of the pointer is at the end.
                while (encryptedStream.Length > encryptedStream.Position)
                {
                    sourceResultEncrypted.Load(context, encryptedStream);

                    //Decrypting -> Decoding -> saving the data into a uLong List
                    List<ulong> finalResultArray = new List<ulong>();

                    using Plaintext plainDataResult = new Plaintext();
                    decryptor.Decrypt(sourceResultEncrypted, plainDataResult);
                    encoder.Decode(plainDataResult, finalResultArray);

                    Console.Write("#" + counter + ": "); //This tells us what line the word is (assuming order hasn't changed)
                    foreach (var item in finalResultArray)
                    {
                        //Print out the values in the word (has integer value). If there is no print out (Because we are ignoring 0's) then we found our word
                        if (item != 0)
                        {
                            Console.Write(item + " ");
                            //Console.Write($"%u{Convert.ToUInt16(item):X4}" + " ");
                        }
                    }

                    Console.WriteLine();
                    counter++;
                }


            }
        }
    }
}
