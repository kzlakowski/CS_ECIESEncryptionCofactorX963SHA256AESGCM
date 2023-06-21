using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Crypto
{
    class Program
    {
        // Alice is sending a message to Bob
        static void Main(string[] args)
        {
            const string message = "secret messeeage!";

            var alice = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
            var bob = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
            Console.WriteLine(Convert.ToBase64String(bob.PublicKey.ExportSubjectPublicKeyInfo()));

            var encrypted = Ecies.Encrypt(bob.PublicKey, Encoding.UTF8.GetBytes(message), HashAlgorithmName.SHA256);
            var decrypted = Ecies.Decrypt(bob, encrypted, HashAlgorithmName.SHA256);

            var result = Encoding.UTF8.GetString(decrypted);

            Console.WriteLine(result);
        }
    }
}