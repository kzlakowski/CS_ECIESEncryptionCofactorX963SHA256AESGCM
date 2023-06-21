using System;

namespace Crypto
{
    /// <summary>
    /// The result of an ECIES encryption operation
    /// </summary>
    public class EciesResult
    {
        /// <summary>
        /// The ephemeral point used to encrypt the data, encoded with X9.62
        /// </summary>
        public byte[] EncodedEphemeralPoint { get; }

        /// <summary>
        /// HMAC of the data
        /// </summary>
        public byte[] Tag { get; }

        /// <summary>
        /// The encrypted data
        /// </summary>
        public byte[] Ciphertext { get; }

        public byte[] Nonce { get; }

        public EciesResult(byte[] encodedEphemeralPoint, byte[] ciphertext, byte[] tag, byte[] nonce)
        {
            EncodedEphemeralPoint = encodedEphemeralPoint ?? throw new ArgumentNullException(nameof(encodedEphemeralPoint));
            Ciphertext = ciphertext ?? throw new ArgumentNullException(nameof(ciphertext));
            Tag = tag ?? throw new ArgumentNullException(nameof(tag));
            Nonce = nonce ?? throw new ArgumentNullException(nameof(nonce));
        }
    }
}