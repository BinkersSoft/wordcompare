using System;
using Xunit;

namespace WordCompare
{
    class TestCode
    {
        //Tests should be placed into a separate project. I created one.
        static void NotMain()
        {
            Console.Write("Do you want to run original code (1) or Mike's code(2): ");
            string choice = Console.ReadLine();
            if (choice == "1")
            {
                Program.BrennanBExample();
            }
            if (choice == "2")
            {
                Program.MikeSExample();
            }
        }
    }
}
