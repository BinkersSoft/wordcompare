using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Microsoft.Research.SEAL;
using Konscious.Security.Cryptography;
using System.Text;
using System.Buffers.Binary;
using System.Diagnostics;
using System.Runtime.CompilerServices;

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
        public static void Main()
        {
            //MikeSExample();
            //BrennanBExample();
            BrennanBExampleWithHashing();
        }

        public static void MikeSExample()
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
    
        public static void BrennanBExample()
        {
            //Load source data to be searched.
            string[] inputData = File.ReadAllLines("words_alpha.txt");
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
            //Used to enable batching
            parms.PlainModulus = PlainModulus.Batching(polyModulusDegree, 20);
            using SEALContext context = new SEALContext(parms);
            using KeyGenerator keygen = new KeyGenerator(context);
            using PublicKey publicKey = keygen.PublicKey;
            using SecretKey secretKey = keygen.SecretKey;
            using Encryptor encryptor = new Encryptor(context, publicKey);
            using Evaluator evaluator = new Evaluator(context);
            using Decryptor decryptor = new Decryptor(context, secretKey);
            using BatchEncoder batchEncoder = new BatchEncoder(context);

            //Declare encrypted variables that cannot be recycled.;
            using Ciphertext sourceDataEncrypted = new Ciphertext();
            using Ciphertext searchDataEncrypted = new Ciphertext();
            using Ciphertext charEncrypted = new Ciphertext();
            using Ciphertext encryptedResult = new Ciphertext();
            using Plaintext plainResult = new Plaintext();
            MemoryStream encryptedStream = new MemoryStream();
            ulong inputFillCharValue = 32;
            //ulong searchFillCharValue = 7;


            List<List<ulong>> inputASCIIData = new List<List<ulong>>();
            List<List<ulong>> searchASCIIData = new List<List<ulong>>();

            //a foreach loop for each file. It converts a word into HEX(which also represents unicode), then into it's integer value
            foreach (var word in inputData)
            {
                inputASCIIData.Add(word.Select(t => (ulong)Convert.ToInt32($"{Convert.ToUInt16(t):X4}", 16)).ToList());
            }

            foreach (var word in searchData)
            {
                searchASCIIData.Add(word.Select(t => (ulong)Convert.ToInt32($"{Convert.ToUInt16(t):X4}", 16)).ToList());
            }

            Console.WriteLine("Initializing arrays.");
            //Hash -> Hex To Dec -> Encode -> Encrypt -> Evaluate -> Decrypt -> Decode -> Dec to Hex -> Compare against hashtable?
            /*
            The total number of batching `slots' equals the PolyModulusDegree, N, and
            these slots are organized into 2-by-(N/2) matrices that can be encrypted and
            computed on. Each slot contains an integer modulo PlainModulus.
            */
            ulong slotCount = batchEncoder.SlotCount;
            ulong rowSize = slotCount / 2;
            //2D arrays do not work
            //ulong[][] inputDataMatrix = new ulong[slotCount][];
            //ulong[][] searchDataMatrix = new ulong[slotCount][];

            List<ulong> inputDataMatrix = new List<ulong>((int)slotCount);
            //List<ulong> searchDataMatrix = new List<ulong>((int)slotCount);

            //Diagram that might help people understand my process
            /*
                My dilemma was convering a 2D array/list of lists into a single array/list.
                I've done this by adding the HEX value for a space inbetween words. (Not sure if this is allowed)
                ASCIIData = [[97, 102, 105, 107], [105, 102, 115, 98]]
                dataMatrix = [97, 102, 105, 107, 32, 105, 102, 115, 98]

            */
            //If searchData length is odd, do the extra loop on the lowCharCount
            int lowNumOfLoops = inputData.Length % 2 == 1 ? (inputData.Length / 2) + 1 : inputData.Length / 2;
            int highNumeOfLoops = inputData.Length / 2;

            //Set the first value equal to a space
            inputDataMatrix.Add(inputFillCharValue);
            //Decided for the simplistic approach of using 2 loops instead of one
            int lowCharCount = 1;
            int inc = 0;
            //Only continue the loop if the increment is below the number of loops AND
            //if the character count + the upcoming word character count + a space is less than the rowSize
            for (; (inc < lowNumOfLoops) && ((lowCharCount + inputASCIIData[inc].ToArray().Length + 1) < (int)rowSize); inc++)
            {
                inputDataMatrix.InsertRange(lowCharCount, inputASCIIData[inc].ToArray());
                //Increase charCount by the number of characters added
                lowCharCount += inputASCIIData[inc].ToArray().Length;
                //Insert word-breaking character
                inputDataMatrix.Insert(lowCharCount, inputFillCharValue);
                //Increment count
                lowCharCount++;
            }

            //Inserts the number of entries that is required to reach the rowSize
            inputDataMatrix.InsertRange(inputDataMatrix.Count - 1, Enumerable.Repeat<ulong>(inputFillCharValue, (int)rowSize - inputDataMatrix.Count).ToArray());

            //Same thing but for the second matrix. Modified placement of values to be increment + rowSize
            int highCharCount = 0;

            for (int i = 0; (i < highNumeOfLoops) && ((highCharCount + inputASCIIData[i + inc].ToArray().Length + 1) < (int)rowSize); i++)
            {
                //Insert at rowsize + charCount
                inputDataMatrix.InsertRange((int)rowSize + highCharCount, inputASCIIData[i + inc].ToArray());
                highCharCount += inputASCIIData[i + inc].ToArray().Length;
                inputDataMatrix.Insert(highCharCount + (int)rowSize, inputFillCharValue);
                highCharCount++;
            }

            Console.WriteLine("Input Data Matrix Created");

            //Set number of loops to proper value
            /*
            lowNumOfLoops = searchData.Length % 2 == 1 ? (searchData.Length / 2) + 1 : searchData.Length / 2;
            highNumeOfLoops = searchData.Length / 2;

            //Reset variables
            lowCharCount = 0;
            inc = 0;

            //Do the same thing except for the search data
            for (; (inc < lowNumOfLoops) && ((lowCharCount + searchHEXData[inc].ToArray().Length + 1) < (int)rowSize); inc++)
            {
                searchDataMatrix.InsertRange(lowCharCount, searchHEXData[inc].ToArray());
                //Increase charCount by the number of characters added
                lowCharCount += searchHEXData[inc].ToArray().Length;
                //Insert word-breaking character
                searchDataMatrix.Insert(lowCharCount, searchFillCharValue); //May have to switch this to 0x20. Not sure yet
                //Increment count
                lowCharCount++;
            }

            //Inserts the number of entries that is required to reach the rowSize
            searchDataMatrix.InsertRange(searchDataMatrix.Count - 1, Enumerable.Repeat<ulong>(searchFillCharValue, (int)rowSize - searchDataMatrix.Count).ToArray());

            highCharCount = 0;

            for (int i = 0; (i < highNumeOfLoops) && ((highCharCount + searchHEXData[i + inc].ToArray().Length + 1) < (int)rowSize); i++)
            {
                //Insert at rowsize + charCount
                searchDataMatrix.InsertRange((int)rowSize + highCharCount, searchHEXData[i + inc].ToArray());
                highCharCount += searchHEXData[i + inc].ToArray().Length;
                searchDataMatrix.Insert(highCharCount + (int)rowSize, searchFillCharValue); //May have to switch this to 0x20. Not sure yet
                highCharCount++;
            }
            */

            //Set the size of the plaintext equal to the size of the matrix
            using Plaintext plainInputMatrix = new Plaintext((ulong)inputDataMatrix.Count, 0);
            batchEncoder.Encode(inputDataMatrix, plainInputMatrix);

            using Plaintext plainSearchValue = new Plaintext();
            batchEncoder.Encode(searchASCIIData[0], plainSearchValue);

            //using Plaintext plainSearchMatrix = new Plaintext((ulong)searchDataMatrix.Count, 0);
            //batchEncoder.Encode(searchDataMatrix, plainSearchMatrix);

            Console.WriteLine("Input Matrix and Search Value Encoded");

            //Encrypt the two plaintext objects
            using Ciphertext encryptedInputMatrix = new Ciphertext(context);
            encryptor.Encrypt(plainInputMatrix, encryptedInputMatrix);

            using Ciphertext encryptedSearchValue = new Ciphertext(context);
            encryptor.Encrypt(plainSearchValue, encryptedSearchValue);

            //using Ciphertext encryptedSearchMatrix = new Ciphertext(context);
            //encryptor.Encrypt(plainSearchMatrix, encryptedSearchMatrix);

            Console.WriteLine("Input Matrix and Search Value Encrypted");

            //Evaluate
            using Ciphertext encryptedNegativeSearchValue = new Ciphertext();
            evaluator.Negate(encryptedSearchValue, encryptedNegativeSearchValue);

            using Ciphertext encryptedResultMatrix = new Ciphertext();

            evaluator.Add(encryptedInputMatrix, encryptedNegativeSearchValue, encryptedResultMatrix);

            Console.WriteLine("Input Matrix and Search Value Evaluated");

            //Decrypt
            using Plaintext plainResultMatrix = new Plaintext();
            decryptor.Decrypt(encryptedResultMatrix, plainResultMatrix);

            Console.WriteLine("Result Matrix Decrypted");

            //Decode
            //[a,e,e,dd,d,f]
            //-
            //[d]
            //=====
            //[3,4,4,00,0,5]
            List<ulong> resultData = new List<ulong>();
            batchEncoder.Decode(plainResultMatrix, resultData);

            Console.WriteLine("Result Decoded");
        }
    
        public static void BrennanBExampleWithHashing()
        {
            string[] inputData = File.ReadAllLines("words_alpha.txt");
            Console.WriteLine("Loaded source data.");

            //Load data to used in search.
            string[] searchData = File.ReadAllLines("search.txt");
            Console.WriteLine("Loaded search data.");

            using EncryptionParameters parms = new EncryptionParameters(SchemeType.BFV);
            ulong polyModulusDegree = 4096;
            parms.PolyModulusDegree = polyModulusDegree;
            parms.CoeffModulus = CoeffModulus.BFVDefault(polyModulusDegree);
            //Used to enable batching
            //33 is because .Batching takes a prime less than 2^x and greater than 2^(x-1) and since we need 32 bits (4 bytes of HEX or 8 HEX values) 
            //which has 16^8 different values, which is enough to cover the entirety of Unicode
            parms.PlainModulus = PlainModulus.Batching(polyModulusDegree, 33); 
            using SEALContext context = new SEALContext(parms);
            using KeyGenerator keygen = new KeyGenerator(context);
            using PublicKey publicKey = keygen.PublicKey;
            using SecretKey secretKey = keygen.SecretKey;
            using Encryptor encryptor = new Encryptor(context, publicKey);
            using Evaluator evaluator = new Evaluator(context);
            using Decryptor decryptor = new Decryptor(context, secretKey);
            using BatchEncoder batchEncoder = new BatchEncoder(context);
            using IntegerEncoder integerEncoder = new IntegerEncoder(context);

            //The input data in HEX form
            List<string> inputHexData = new List<string>();
            string searchHexValue = "";
            byte[] salt = BitConverter.GetBytes(12345678); //Updated version - https://stackoverflow.com/questions/4176653/int-to-byte-array
            var argon2 = new Argon2d(Encoding.ASCII.GetBytes(searchData[1]));

            argon2.DegreeOfParallelism = 2;
            argon2.MemorySize = 32;
            argon2.Iterations = 2;
            argon2.Salt = salt;

            //****Normally would just go immediately to Dec(ulong) but want to see how the Hex will work out****
            searchHexValue = BitConverter.ToString(argon2.GetBytes(4)).Replace("-", string.Empty);

            //Loops through polyModulusDegree number of times (4096 in this case), hashes the word, then adds it to the list
            for (int i = 0; i < (int)parms.PolyModulusDegree; i++)
            {
                argon2 = new Argon2d(Encoding.ASCII.GetBytes(inputData[i]));
                argon2.DegreeOfParallelism = 2;
                argon2.MemorySize = 32;
                argon2.Iterations = 2;
                argon2.Salt = salt;

                inputHexData.Add(BitConverter.ToString(argon2.GetBytes(4)).Replace("-", string.Empty));
            }

            argon2.Dispose();
            //Create the searchValue
            ulong searchASCIIValue = Convert.ToUInt64(searchHexValue, 16);
            //Create a matrix filled with the search value
            List<ulong> searchASCIIMatrix = Enumerable.Repeat<ulong>(searchASCIIValue, (int)parms.PolyModulusDegree).ToList();
            //Create a matrix from the input values
            List<ulong> inputASCIIMatrix = new List<ulong>((int)parms.PolyModulusDegree);

            foreach (var hex in inputHexData)
            {
                inputASCIIMatrix.Add(Convert.ToUInt64(hex, 16));
            }

            Console.WriteLine("ASCII Matrix and Search Value Created");

            //Set the size of the plaintext equal to the size of the matrix
            using Plaintext plainInputMatrix = new Plaintext((ulong)inputASCIIMatrix.Count, 0);
            batchEncoder.Encode(inputASCIIMatrix, plainInputMatrix);

            using Plaintext plainSearchMatrix = new Plaintext((ulong)searchASCIIMatrix.Count, 0);
            batchEncoder.Encode(searchASCIIMatrix, plainSearchMatrix);

            Console.WriteLine("Input Matrix and Search Value Encoded");

            //Encrypt the two plaintext objects
            using Ciphertext encryptedInputMatrix = new Ciphertext(context);
            encryptor.Encrypt(plainInputMatrix, encryptedInputMatrix);

            using Ciphertext encryptedSearchMatrix = new Ciphertext(context);
            encryptor.Encrypt(plainSearchMatrix, encryptedSearchMatrix);

            Console.WriteLine("Input Matrix and Search Value Encrypted");

            //Evaluate
            using Ciphertext encryptedResultMatrix = new Ciphertext(context);
            evaluator.Sub(encryptedInputMatrix, encryptedSearchMatrix, encryptedResultMatrix);

            Console.WriteLine("Input Matrix and Search Value Evaluated");

            //Decrypt
            using Plaintext plainResultMatrix = new Plaintext();
            decryptor.Decrypt(encryptedResultMatrix, plainResultMatrix);

            Console.WriteLine("Result Matrix Decrypted");

            //Decode
            List<ulong> resultData = new List<ulong>();
            batchEncoder.Decode(plainResultMatrix, resultData);

            Console.WriteLine("Result Matrix Decoded");

            if (resultData.FindIndex(x => x == 0) != -1)
            {
                Console.WriteLine("Match found");
            }
            
        }
    }


}
