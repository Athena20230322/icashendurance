using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace GetToken
{
    class Program
    {
        static void Main(string[] args)
        {
            ICP.KeyExchange.TestLibrary.Test.CertificateApiTest cf = new ICP.KeyExchange.TestLibrary.Test.CertificateApiTest();
            cf.GetCellphone();
            Console.ReadLine();
        }
    }
}
