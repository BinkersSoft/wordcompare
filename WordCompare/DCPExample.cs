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
        private Evaluator evaluator { get; set; }
        private Decryptor decryptor { get; set; }

        //Encoders
        private BatchEncoder batchEncoder { get; set; }
        //private IntegerEncoder integerEncoder { get; set; }

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
            evaluator = new Evaluator(context);
            decryptor = new Decryptor(context, secretKey);
            batchEncoder = new BatchEncoder(context);
            //integerEncoder = new IntegerEncoder(context);

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
            if (inputData == null || inputData.Length == 0)
            {
                throw new InvalidOperationException("Ensure input data exists before hashing");
            }
            Console.WriteLine("Hashing Data. This may take a while");
    
            for (int i = 0; i < inputData.Length; i++) 
            {
                //Create hash
                argon2 = new Argon2d(Encoding.ASCII.GetBytes(inputData[i]));

                argon2.DegreeOfParallelism = 2;
                argon2.MemorySize = 32;
                argon2.Iterations = 1;
                argon2.Salt = salt;

                //Converts from bytes, to hex (removes dashes), to ulongs
                hashedInputData.Add((ulong)BitConverter.ToUInt32(argon2.GetBytes(4)));
            }

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
            int arraySize = hashedInputData.Count;

            for (int i = 0; i < Math.Ceiling((double)hashedInputData.Count / parms.PolyModulusDegree); i++)
            {
                using Plaintext plainDataMatrix = new Plaintext((ulong)parms.PolyModulusDegree, 0);
                batchEncoder.Encode(hashedInputData.GetRange(i * (int)parms.PolyModulusDegree, Math.Min((int)parms.PolyModulusDegree, arraySize)), plainDataMatrix);

                arraySize -= (int)parms.PolyModulusDegree;

                using Ciphertext encryptedDataMatrix = new Ciphertext(context);
                encryptor.Encrypt(plainDataMatrix, encryptedDataMatrix);

                encryptedDataList.Add(new Ciphertext(encryptedDataMatrix));
            }

            return encryptedDataList.Count;
        }


        public bool search(string searchWord)
        {
            Stopwatch sw = new Stopwatch();
            sw.Start();
            if (encryptedDataList.Count == 0)
            {
                throw new InvalidOperationException("The ciphertexts must be created before searching them");
            }
            //Hash the search word
            argon2 = new Argon2d(Encoding.ASCII.GetBytes(searchWord));
            bool matchFound = false;

            argon2.DegreeOfParallelism = 2;
            argon2.MemorySize = 32;
            argon2.Iterations = 1;
            argon2.Salt = salt;

            //Converts from bytes, to hex (removes dashes), to ulongs
            ulong searchValue = (ulong)BitConverter.ToUInt32(argon2.GetBytes(4));
            argon2.Dispose();

            List<ulong> searchValueMatrix = Enumerable.Repeat<ulong>(searchValue, (int)parms.PolyModulusDegree).ToList();

            using Plaintext plainSearchValueMatrix = new Plaintext();
            batchEncoder.Encode(searchValueMatrix, plainSearchValueMatrix);

            using Ciphertext encryptedSearchValue = new Ciphertext(context);
            encryptor.Encrypt(plainSearchValueMatrix, encryptedSearchValue);
            Console.Write("Searching");
            int index = 0;
            while (!matchFound && index < encryptedDataList.Count)
            {
                Console.Write(".");
                using Plaintext plainTest = new Plaintext();
                decryptor.Decrypt(encryptedDataList[index], plainTest);

                List<ulong> list = new List<ulong>();
                batchEncoder.Decode(plainTest, list);

                MemoryStream memStream = new MemoryStream();
                //Will (in order) load in the parameters, searchValue, and inputData
                //Save parameters
                parms.Save(memStream, ComprModeType.Deflate);

                //Save search value
                encryptedSearchValue.Save(memStream, ComprModeType.Deflate);

                //Save input data
                encryptedDataList[index].Save(memStream, ComprModeType.Deflate);

                //Seek to the start
                memStream.Seek(0, SeekOrigin.Begin);

                //Compute that memoryStream
                MemoryStream resultMemStream = compute(memStream);

                //Load into a Ciphertext
                using Ciphertext encryptedResults = new Ciphertext();
                encryptedResults.Load(context, resultMemStream);

                //Decrypt
                using Plaintext plainResults = new Plaintext((ulong)parms.PolyModulusDegree, 0);
                decryptor.Decrypt(encryptedResults, plainResults);

                //Decode
                List<ulong> resultMatrix = new List<ulong>();
                batchEncoder.Decode(plainResults, resultMatrix);

                //Process
                //***Run example where the last list contains the matched word (Will break it)***
                matchFound = resultMatrix.FindIndex(x => x == 0) != -1;

                resultMemStream.Dispose();
                index++;
            }
            sw.Stop();
            Console.WriteLine("Total time: " + sw.ElapsedMilliseconds);
            return matchFound;
        }

        private static MemoryStream compute(MemoryStream memStream)
        {
            EncryptionParameters parms = new EncryptionParameters();
            parms.Load(memStream);

            SEALContext context = new SEALContext(parms);

            using Evaluator evaluator = new Evaluator(context);

            using Ciphertext encryptedSearchValue = new Ciphertext();
            encryptedSearchValue.Load(context, memStream);

            using Ciphertext encryptedDataMatrix = new Ciphertext();
            encryptedDataMatrix.Load(context, memStream);

            using Ciphertext encryptedDataResult = new Ciphertext();

            evaluator.Sub(encryptedDataMatrix, encryptedSearchValue, encryptedDataResult);

            MemoryStream returnMemStream = new MemoryStream();
            encryptedDataResult.Save(returnMemStream, ComprModeType.Deflate);

            //Seek to the start
            returnMemStream.Seek(0, SeekOrigin.Begin);

            //Dispose everything (Unsure if necessary)
            memStream.Dispose();
            encryptedSearchValue.Dispose();
            encryptedDataMatrix.Dispose();
            encryptedDataResult.Dispose();
            evaluator.Dispose();
            context.Dispose();
            parms.Dispose();

            return returnMemStream;
        }
        
  

    }
}
