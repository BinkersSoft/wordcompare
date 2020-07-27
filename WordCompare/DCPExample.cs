using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Microsoft.Research.SEAL;
using Konscious.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;
using System.Text.RegularExpressions;

namespace WordCompare
{
    public class DCPExample
    {
        //Data
        private string[] inputData { get; set; }
        private List<ulong> hashedInputData { get; set; }
        private List<Ciphertext> encryptedDataList { get; set; }

        //SEAL
        private EncryptionParameters parms { get; set;}
        private SEALContext context { get; set; }
        private KeyGenerator keygen { get; set; }
        private PublicKey publicKey { get; set; }
        private SecretKey secretKey { get; set; }
        private Encryptor encryptor { get; set; }
        private Decryptor decryptor { get; set; }

        //Encoders
        private BatchEncoder batchEncoder { get; set; }

        //Argon2
        private Argon2d argon2 { get; set; }
        private byte[] salt { get; set; }

        public DCPExample(ulong polyModulusDegree)
        {
            //Data
            hashedInputData = new List<ulong>();
            encryptedDataList = new List<Ciphertext>();

            //SEAL
            parms = new EncryptionParameters(SchemeType.BFV);
            parms.PolyModulusDegree = polyModulusDegree;
            parms.CoeffModulus = CoeffModulus.BFVDefault(polyModulusDegree);
            //Used to enable batching
            //33 is because .Batching takes a prime less than 2^x and greater than 2^(x-1) and since we need 32 bits (4 bytes of HEX or 8 HEX values) 
            //which has 16^8 different values, which is enough to cover the entirety of Unicode
            parms.PlainModulus = PlainModulus.Batching(polyModulusDegree, 33);
            context = new SEALContext(parms);
            keygen = new KeyGenerator(context);
            publicKey = keygen.PublicKey;
            secretKey = keygen.SecretKey;
            encryptor = new Encryptor(context, publicKey);
            decryptor = new Decryptor(context, secretKey);
            batchEncoder = new BatchEncoder(context);

            //Default value for salt
            salt = BitConverter.GetBytes(12345678);
        }

        public void loadInputData(string[] inputData)
        {
            this.inputData = inputData;
        }

        /// <summary>
        /// Hashes the input data file and writes out the hashes to the specified path as a bin file
        /// </summary>
        /// <param name="path">Location of the bin file</param>
        public void hashInputData(string path = "HashedInputData.bin")
        {
            Stopwatch sw = new Stopwatch();
            if (inputData == null || inputData.Length == 0)
            {
                throw new InvalidOperationException("Ensure input data exists before hashing");
            }
            Console.WriteLine("Hashing Data. This may take a while");
            sw.Start();
            for (int i = 0; i < inputData.Length; i++) 
            {
                //Create hash
                argon2 = new Argon2d(Encoding.ASCII.GetBytes(inputData[i]));

                argon2.DegreeOfParallelism = 1;
                argon2.MemorySize = 4;
                argon2.Iterations = 1;
                argon2.Salt = salt;

                //Converts from bytes, to hex (removes dashes), to ulongs
                hashedInputData.Add((ulong)BitConverter.ToUInt32(argon2.GetBytes(4)));
            }
            sw.Stop();
            Console.WriteLine("Total time to hash: " + sw.ElapsedMilliseconds);

            writeHashedInputData(path);
        }

        /// <summary>
        /// NOTE: If a file already exists in the set location, it will be deleted
        /// </summary>
        /// <param name="path">The relative location of the file</param>
        private void writeHashedInputData(string path)
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }

            //hashedInputData
            var byteData = new byte[hashedInputData.Count * sizeof(UInt64)];
            Buffer.BlockCopy(hashedInputData.ToArray(), 0, byteData, 0, byteData.Length);

            FileStream fs = new FileStream(path, FileMode.CreateNew);
            BinaryWriter binWriter = new BinaryWriter(fs);
            binWriter.Write(hashedInputData.Count);
            binWriter.Write(byteData);
            binWriter.Dispose();
        }

        public void readHashedInputData(string path = "HashedInputData.bin")
        {
            if (!File.Exists(path))
            {
                throw new FileNotFoundException("File does not exist");
            }

            FileStream fs = new FileStream(path, FileMode.Open);
            BinaryReader binReader = new BinaryReader(fs);
            int listLength = binReader.ReadInt32();
            byte[] byteData = binReader.ReadBytes(listLength * sizeof(UInt64));

            var hashedDataArray = new UInt64[listLength];
            Buffer.BlockCopy(byteData, 0, hashedDataArray, 0, byteData.Length);
            binReader.Dispose();
            this.hashedInputData = hashedDataArray.ToList();
        }

        /// <summary>
        /// Takes the hashedInputData and creates x number of lists where x = InputData length / PolyModulusDegree
        /// </summary>
        /// <returns>The number of lists created</returns>
        public int setupCiphers()
        {
            //Set a variable equal to the total size of hashed data
            int arraySize = hashedInputData.Count;

            //Loop through x amount of times where x = (total hashed input count) / (polyModulusDegree) rounded up
            for (int i = 0; i < Math.Ceiling((double)hashedInputData.Count / parms.PolyModulusDegree); i++)
            {
                //Create a Plaintext to store the range of hashed values
                using Plaintext plainDataMatrix = new Plaintext((ulong)parms.PolyModulusDegree, 0);

                //Examples of the list if there is 10,000 hashed items with a polyModDegree of 4096. List1 = 0-4095, List2 = 4096-8191, List3 = 8192-10000
                batchEncoder.Encode(hashedInputData.GetRange(i * (int)parms.PolyModulusDegree, Math.Min((int)parms.PolyModulusDegree, arraySize)), plainDataMatrix);

                //Decrement the number used to calculate the array size
                arraySize -= (int)parms.PolyModulusDegree;

                //Encrypt the data
                using Ciphertext encryptedDataMatrix = new Ciphertext(context);
                encryptor.Encrypt(plainDataMatrix, encryptedDataMatrix);

                //Add it to the data list
                encryptedDataList.Add(new Ciphertext(encryptedDataMatrix));
            }

            //Return the number of lists (can be used to determine how many jobs to process for the DCP)
            return encryptedDataList.Count;
        }


        public int search(string searchWord)
        {
            Stopwatch sw = new Stopwatch();
            sw.Start();
            if (encryptedDataList.Count == 0)
            {
                throw new InvalidOperationException("The ciphertexts must be created before searching them");
            }

            bool matchFound = false;

            //Hash the search word
            argon2 = new Argon2d(Encoding.ASCII.GetBytes(searchWord));
            
            argon2.DegreeOfParallelism = 1;
            argon2.MemorySize = 4;
            argon2.Iterations = 1;
            argon2.Salt = salt;

            //Converts from bytes to ulong
            ulong searchValue = (ulong)BitConverter.ToUInt32(argon2.GetBytes(4));
            argon2.Dispose();

            //Create a list of the search word repeated
            List<ulong> searchValueMatrix = Enumerable.Repeat<ulong>(searchValue, (int)parms.PolyModulusDegree).ToList();

            //Encode it
            using Plaintext plainSearchValueMatrix = new Plaintext();
            batchEncoder.Encode(searchValueMatrix, plainSearchValueMatrix);

            //Encrypt it
            using Ciphertext encryptedSearchValue = new Ciphertext(context);
            encryptor.Encrypt(plainSearchValueMatrix, encryptedSearchValue);

            //Start the search
            Console.Write("Searching");
            int index = 0;

            int totalWordCount = 0;

            //Search for single and stop
            //while (!matchFound && index < encryptedDataList.Count)
            while (index < encryptedDataList.Count)
            {
                //Writing out the . gives a sense of progression
                Console.Write(".");

                //Create a MemoryStream
                //Will (in order) load in the parameters, searchValue, and inputData
                MemoryStream memStream = new MemoryStream();
                
                //Save parameters
                parms.Save(memStream, ComprModeType.Deflate);

                //Save search value
                encryptedSearchValue.Save(memStream, ComprModeType.Deflate);

                //Save input data
                encryptedDataList[index].Save(memStream, ComprModeType.Deflate);

                //Seek to the start
                memStream.Seek(0, SeekOrigin.Begin);

                //Compute on that memoryStream (This is where the DCP method will be)
                MemoryStream resultMemStream = compute(memStream);

                //Load results into a Ciphertext
                using Ciphertext encryptedResults = new Ciphertext();
                encryptedResults.Load(context, resultMemStream);

                //Decrypt
                using Plaintext plainResults = new Plaintext((ulong)parms.PolyModulusDegree, 0);
                decryptor.Decrypt(encryptedResults, plainResults);

                //Decode
                List<ulong> resultMatrix = new List<ulong>();
                batchEncoder.Decode(plainResults, resultMatrix);

                //Process reults
                int count = resultMatrix.FindAll(x => x == 0).Count;
                matchFound = count > 0;

                //Add to counter if matchFound
                if (matchFound) { totalWordCount += count; }

                //Dispose of the memory stream
                resultMemStream.Dispose();
                
                index++;
            }
            sw.Stop();
            Console.WriteLine("\nTotal time (ms): " + sw.ElapsedMilliseconds);
            Console.WriteLine("Search speed (words/s): " + ((ulong)index * parms.PolyModulusDegree) / ((ulong)sw.ElapsedMilliseconds / 1000));
            return totalWordCount;
        }

        private static MemoryStream compute(MemoryStream memStream)
        {
            //Load the variables from the memory stream
            EncryptionParameters parms = new EncryptionParameters();
            parms.Load(memStream);

            //Create the context and evaluator based on the parms
            SEALContext context = new SEALContext(parms);
            using Evaluator evaluator = new Evaluator(context);

            //Create the search Ciphertext
            using Ciphertext encryptedSearchValue = new Ciphertext();
            encryptedSearchValue.Load(context, memStream);

            //Create the data Ciphertext
            using Ciphertext encryptedDataMatrix = new Ciphertext();
            encryptedDataMatrix.Load(context, memStream);

            //Create the result Ciphertext and do the subtraction between the two ciphertexts
            using Ciphertext encryptedDataResult = new Ciphertext();
            evaluator.Sub(encryptedDataMatrix, encryptedSearchValue, encryptedDataResult);

            //Create the return memory stream and save the results to it
            MemoryStream returnMemStream = new MemoryStream();
            encryptedDataResult.Save(returnMemStream, ComprModeType.Deflate);

            //Seek to the start
            returnMemStream.Seek(0, SeekOrigin.Begin);

            //Dispose everything (Unsure if necessary)
            //memStream.Dispose();
            //encryptedSearchValue.Dispose();
            //encryptedDataMatrix.Dispose();
            //encryptedDataResult.Dispose();
            //evaluator.Dispose();
            context.Dispose();
            parms.Dispose();

            return returnMemStream;
            //Since Tuesday I've been working on making my demo much more efficient and the total hashing time is now about 55% of what it use to be. I've also been going through the DCP trying 
            //to figure a way to connect C# with JavaScript and still haven't found anything that will work well
        }
        
  

    }
}
