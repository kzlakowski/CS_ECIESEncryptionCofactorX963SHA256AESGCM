using System;
using System.Buffers.Text;
using System.Security.Cryptography;


// ReSharper disable SuggestVarOrType_SimpleTypes - BCL rules
namespace Crypto
{
    /// <summary>
    /// Simple implementation of ECIES (Elliptic Curve Integrated Encryption Scheme) based on http://www.secg.org/sec1-v2.pdf, section 5.1
    /// Things not implemented:
    /// - Encoding parameters using compressed points; only uncompressed points are used
    /// - This implementation does not use the optional SharedInfo1 & SharedInfo2 parameters
    /// - The KDF and cipher are fixed as ANSI-X9.63-KDF and AES-256-CBC, but the HMAC hash algorithm can be specified
    /// </summary>
    public static class Ecies
    {
        private static readonly byte[] KdfCounter1 = { 0, 0, 0, 1 };
        private static readonly byte[] KdfCounter2 = { 0, 0, 0, 2 };

        /// <summary>
        /// Based on http://www.secg.org/sec1-v2.pdf, section 5.1.3
        /// Encrypt data using ECIES (Elliptic Curve Integrated Encryption Scheme)
        /// </summary>
        /// <param name="recipientPubKey">Public key of the recipient</param>
        /// <param name="data">𝑀, the message to be encrypted</param>
        /// <param name="hashAlgorithm">Hash algorithm to use to generate an HMAC of the encrypted data</param>
        /// <returns>A result containing the elliptic curve parameters, encrypted message and HMAC (R̄, 𝐸𝑀, 𝐷̄)</returns>
        public static EciesResult Encrypt(ECDiffieHellmanPublicKey recipientPubKey, byte[] data, HashAlgorithmName hashAlgorithm)
        {
            if (recipientPubKey == null)
                throw new ArgumentNullException(nameof(recipientPubKey));
            if (data == null)
                throw new ArgumentNullException(nameof(data));
            if (string.IsNullOrEmpty(hashAlgorithm.Name))
                throw new ArgumentException("Hash algorithm name must have a value", nameof(hashAlgorithm));

            ECCurve curve = recipientPubKey.ExportParameters().Curve;

            // Generate an ephemeral keypair on the correct curve
            using (ECDiffieHellman ephemeral = ECDiffieHellman.Create(curve))
            {
                // encodedEphemeralPoint (R)̄ contains the parameters to be used for encryption/decryption operations, encoded using X9.62
                ECParameters ephemPublicParams = ephemeral.ExportParameters(false);
                int pointLen = ephemPublicParams.Q!.X!.Length;
                byte[] encodedEphemeralPoint = new byte[pointLen * 2 + 1];
                encodedEphemeralPoint[0] = 0x04; // Uncompressed point
                Buffer.BlockCopy(ephemPublicParams.Q.X, 0, encodedEphemeralPoint, 1, pointLen);
                Buffer.BlockCopy(ephemPublicParams.Q!.Y!, 0, encodedEphemeralPoint, 1 + pointLen, pointLen);

                // Use ANSI-X9.63-KDF to derive the encryption key, 𝐸𝐾
                byte[] encryptionKey = ephemeral.DeriveKeyFromHash(recipientPubKey, HashAlgorithmName.SHA256, null, KdfCounter1);

                // Use ANSI-X9.63-KDF to derive the HMAC key, 𝑀𝐾
                byte[] hmacKey = ephemeral.DeriveKeyFromHash(recipientPubKey, HashAlgorithmName.SHA256, null, KdfCounter2);

                // The ciphertext, 𝐸𝑀
                byte[] ciphertext = new byte[data.Length];

                // Use AES-256-CBC to encrypt the message
                // Note we use an empty IV - this is OK, as the key is never reused (see section 3.8 of the spec)
                Console.WriteLine("Creating aes gcm");
                AesGcm aesGcm = new AesGcm(encryptionKey);
                var nonce = new byte[AesGcm.NonceByteSizes.MaxSize]; // MaxSize = 12
                RandomNumberGenerator.Fill(nonce);
                var tag = new byte[AesGcm.TagByteSizes.MaxSize];
                Console.WriteLine("Encrypting");
                aesGcm.Encrypt(nonce, data, ciphertext, tag);

                return new EciesResult(encodedEphemeralPoint, ciphertext, tag, nonce);
            }
        }

        /// <summary>
        /// Based on http://www.secg.org/sec1-v2.pdf, section 5.1.4
        /// Decrypt data using ECIES (Elliptic Curve Integrated Encryption Scheme)
        /// </summary>
        /// <param name="recipient">Recipient of the message</param>
        /// <param name="encryptionResult">The result of an ECIES encryption operation</param>
        /// <param name="hashAlgorithm">Hash algorithm to use to verify the HMAC of the encrypted data</param>
        /// <returns>The decrypted message</returns>
        public static byte[] Decrypt(ECDiffieHellman recipient, EciesResult encryptionResult, HashAlgorithmName hashAlgorithm)
        {
            if (recipient == null)
                throw new ArgumentNullException(nameof(recipient));
            if (encryptionResult == null)
                throw new ArgumentNullException(nameof(encryptionResult));
            if (encryptionResult.EncodedEphemeralPoint.Length == 0 || encryptionResult.EncodedEphemeralPoint[0] != 0x04)
                throw new ArgumentOutOfRangeException(nameof(encryptionResult), "Encoded ephemeral point not in correct formtat - expected first byte to be 0x04 (uncompressed point)");
            if (encryptionResult.Ciphertext == null)
                throw new ArgumentException("Ciphertext must has a value", nameof(encryptionResult.Ciphertext));
            if (encryptionResult.Tag == null)
                throw new ArgumentException("Tag (HMAC) must have a value", nameof(encryptionResult.Tag));

            ECParameters recipientParams = recipient.ExportParameters(false);
            int pointLen = recipientParams.Q!.X!.Length;
            int expectedRLen = 1 + pointLen * 2;

            if (encryptionResult.EncodedEphemeralPoint.Length < expectedRLen)
                throw new ArgumentOutOfRangeException(nameof(encryptionResult.EncodedEphemeralPoint), $"Incorrect length for curve parameters - expected {expectedRLen} bytes");

            // Extract the ephemeral elliptic curve point R=(xR, yR) from R̄
            var ecParameters = new ECParameters
            {
                Curve = recipientParams.Curve,
                Q =
                {
                    X = new byte[pointLen],
                    Y = new byte[pointLen]
                }
            };
            Buffer.BlockCopy(encryptionResult.EncodedEphemeralPoint, 1, ecParameters.Q.X, 0, pointLen);
            Buffer.BlockCopy(encryptionResult.EncodedEphemeralPoint, pointLen + 1, ecParameters.Q.Y, 0, pointLen);
            ecParameters.Validate();

            // 𝑀, the plaintext
            byte[] plaintext = new byte[encryptionResult.Ciphertext.Length];
            using (ECDiffieHellman senderEcdh = ECDiffieHellman.Create(ecParameters))
            using (ECDiffieHellmanPublicKey senderPublicKey = senderEcdh.PublicKey)
            {
                // Use ANSI-X9.63-KDF to derive the encryption key, 𝐸𝐾
                byte[] encryptionKey = recipient.DeriveKeyFromHash(senderPublicKey, HashAlgorithmName.SHA256, null, new byte[] { 0, 0, 0, 1 });

                // Use ANSI-X9.63-KDF to derive the HMAC key, 𝑀𝐾
                byte[] hmacKey = recipient.DeriveKeyFromHash(senderPublicKey, HashAlgorithmName.SHA256, null, new byte[] { 0, 0, 0, 2 });

                // Use AES-256-CBC to decrypt the message
                // Note we use an empty IV - this is OK, as the key is never reused (see section 3.8 of the spec)
                AesGcm aesGcm = new(encryptionKey);
                Console.WriteLine("Decrypting");
                aesGcm.Decrypt(encryptionResult.Nonce, encryptionResult.Ciphertext, encryptionResult.Tag, plaintext);
            }

            return plaintext;
        }

        private static byte[] ComputeHMAC(HashAlgorithmName hashAlgorithmName, byte[] key, byte[] data)
        {
            using (IncrementalHash hmac = IncrementalHash.CreateHMAC(hashAlgorithmName, key))
            {
                hmac.AppendData(data);
                return hmac.GetHashAndReset();
            }
        }

        private static int ComputeHMAC(HashAlgorithmName hashAlgorithmName, byte[] key, byte[] data, Span<byte> output)
        {
            // Check if output is big enough for the hash
            var hashLen = HashLength(hashAlgorithmName);
            if (output.Length < hashLen)
                throw new ArgumentException($"Output buffer is not large enough for the hash result ({hashLen} bytes are required)", nameof(output));

            using (IncrementalHash hmac = IncrementalHash.CreateHMAC(hashAlgorithmName, key))
            {
                hmac.AppendData(data);

                if (!hmac.TryGetHashAndReset(output, out int bytesWritten))
                {
                    throw new CryptographicException("HMAC operation failed unexpectedly");
                }

                return bytesWritten;
            }
        }

        private static int HashLength(HashAlgorithmName hashAlgorithmName)
        {
            if (hashAlgorithmName == HashAlgorithmName.SHA1)
            {
                return 160 / 8;
            }
            else if (hashAlgorithmName == HashAlgorithmName.SHA256)
            {
                return 256 / 8;
            }
            else if (hashAlgorithmName == HashAlgorithmName.SHA384)
            {
                return 384 / 8;
            }
            else if (hashAlgorithmName == HashAlgorithmName.SHA512)
            {
                return 512 / 8;
            }
            else if (hashAlgorithmName == HashAlgorithmName.MD5)
            {
                return 128 / 8;
            }
            else
            {
                throw new ArgumentOutOfRangeException(nameof(hashAlgorithmName));
            }
        }
    }
}