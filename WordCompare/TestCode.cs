using System;
using Xunit;

namespace WordCompare
{
    class Program
    {
        static void Main()
        {
            Console.Write("Do you want to run original code (1) or Mike's code(2): ");
            string choice = Console.ReadLine();
            if (choice == "1")
            {
                Program1.OrigionalExample();
            }
            if (choice == "2")
            {
                MikeSCode.BatchEncoderExample();
            }
        }
    }
}