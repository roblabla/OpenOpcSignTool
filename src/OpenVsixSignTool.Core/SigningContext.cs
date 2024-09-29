using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Runtime.InteropServices;

namespace OpenVsixSignTool.Core
{
    /// <summary>
    /// A signing context used for signing packages with Azure Key Vault Keys.
    /// </summary>
    public class SigningContext : ISigningContext
    {
        private readonly SignConfigurationSet _configuration;

        /// <summary>
        /// Creates a new siging context.
        /// </summary>
        public SigningContext(SignConfigurationSet configuration)
        {
            ContextCreationTime = DateTimeOffset.Now;
            _configuration = configuration;
        }

        /// <summary>
        /// Gets the date and time that this context was created.
        /// </summary>
        public DateTimeOffset ContextCreationTime { get; }

        /// <summary>
        /// Gets the file digest algorithm.
        /// </summary>
        public HashAlgorithmName FileDigestAlgorithmName => _configuration.FileDigestAlgorithm;

        /// <summary>
        /// Gets the certificate and public key used to validate the signature.
        /// </summary>
        public X509Certificate2 Certificate => _configuration.PublicCertificate;

        /// <summary>
        /// Gets the signature algorithm.
        /// </summary>
        public SigningAlgorithm SignatureAlgorithm
        {
            get
            {
                switch (_configuration.SigningKey)
                {
                    case RSA _: return SigningAlgorithm.RSA;
                    case ECDsa _: return SigningAlgorithm.ECDSA;
                    default: return SigningAlgorithm.Unknown;
                }
            }
        }


        /// <summary>
        /// Gets the XmlDSig identifier for the configured algorithm.
        /// </summary>
        public Uri XmlDSigIdentifier => SignatureAlgorithmTranslator.SignatureAlgorithmToXmlDSigUri(SignatureAlgorithm, _configuration.SignatureDigestAlgorithm);


        /// <summary>
        /// Signs a digest.
        /// </summary>
        /// <param name="digest">The digest to sign.</param>
        /// <returns>The signature of the digest.</returns>
        public byte[] SignDigest(byte[] digest)
        {
            switch (_configuration.SigningKey)
            {
                case RSAOpenSsl rsaOpenSsl:
                    return SignHashNotBroken(rsaOpenSsl, digest, _configuration.SignatureDigestAlgorithm);
                case RSA rsa:
                    return rsa.SignHash(digest, _configuration.SignatureDigestAlgorithm, RSASignaturePadding.Pkcs1);
                case ECDsa ecdsa:
                    return ecdsa.SignHash(digest);
                default:
                    throw new InvalidOperationException("Unknown signing algorithm.");
            }
        }

        [DllImport("libcrypto.so", CharSet=CharSet.Ansi)]
        private static extern int EVP_PKEY_size(IntPtr evp_pkey);

        [DllImport("libcrypto.so", CharSet=CharSet.Ansi)]
        private static extern IntPtr EVP_sha1();

        [DllImport("libcrypto.so", CharSet=CharSet.Ansi)]
        private static extern IntPtr EVP_sha256();

        [DllImport("libcrypto.so", CharSet=CharSet.Ansi)]
        private static extern IntPtr EVP_PKEY_CTX_new(IntPtr evp_pkey, IntPtr engine);

        [DllImport("libcrypto.so", CharSet=CharSet.Ansi)]
        private static extern void EVP_PKEY_CTX_free(IntPtr evp_pkey_ctx);

        [DllImport("libcrypto.so", CharSet=CharSet.Ansi)]
        private static extern int EVP_PKEY_sign_init(IntPtr evp_pkey_ctx);

        //[DllImport("libcrypto.so", CharSet=CharSet.Ansi)]
        //private static extern int EVP_PKEY_CTX_set_rsa_padding(IntPtr evp_pkey_ctx, int pad);

        [DllImport("libcrypto.so", CharSet=CharSet.Ansi)]
        private static extern int RSA_pkey_ctx_ctrl(IntPtr evp_pkey_ctx, int optype, int cmd, int p1, IntPtr p2);

        //[DllImport("libcrypto.so", CharSet=CharSet.Ansi)]
        //private static extern int EVP_PKEY_CTX_set_signature_md(IntPtr evp_pkey_ctx, IntPtr evp_md);

        [DllImport("libcrypto.so", CharSet=CharSet.Ansi)]
        private static extern int EVP_PKEY_CTX_ctrl(IntPtr evp_pkey_ctx, int keytype, int optype, int cmd, int p1, IntPtr p2);

        [DllImport("libcrypto.so", CharSet=CharSet.Ansi)]
        private static extern int EVP_PKEY_sign(IntPtr evp_pkey_ctx, byte[] sig, ref nuint siglen, byte[] tbs, IntPtr tbslen);

        static DeferDisposable Defer(Action action) => new DeferDisposable(action);

        internal readonly struct DeferDisposable : IDisposable
        {
            readonly Action _action;
            public DeferDisposable(Action action) => _action = action;
            public void Dispose() => _action.Invoke();
        }

        private byte[] SignHashNotBroken(RSAOpenSsl rsa, byte[] hash, HashAlgorithmName digestAlgorithm) {
            using SafeEvpPKeyHandle key = rsa.DuplicateKeyHandle();
            int bytesRequired = EVP_PKEY_size(key.DangerousGetHandle());
            byte[] signature = new byte[bytesRequired];
            IntPtr digestAlgorithmPtr = IntPtr.Zero;

            switch(digestAlgorithm.Name) {
                case "SHA1":
                    digestAlgorithmPtr = EVP_sha1();
                    break;
                case "SHA256":
                    digestAlgorithmPtr = EVP_sha256();
                    break;
                default:
                    throw new Exception();
            }

            if (digestAlgorithmPtr == IntPtr.Zero) {
                throw new Exception();
            }

            IntPtr ctx = EVP_PKEY_CTX_new(key.DangerousGetHandle(), IntPtr.Zero);
            if (ctx == IntPtr.Zero) {
                throw new Exception();
            }
            using var defer = Defer(() => { EVP_PKEY_CTX_free(ctx); });

            if (EVP_PKEY_sign_init(ctx) <= 0) {
                throw new Exception();
            }

            int RSA_PKCS1_PADDING = 1;
            //if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0)
            if (RSA_pkey_ctx_ctrl(ctx, -1, /* RSA_PKCS1_PADDING */ 0x1001, RSA_PKCS1_PADDING, IntPtr.Zero) <= 0)
            {
                throw new Exception();
            }

            //if (EVP_PKEY_CTX_set_signature_md(ctx, digestAlgorithmPtr) <= 0)
            if (EVP_PKEY_CTX_ctrl(ctx, -1, /* EVP_PKEY_OP_TYPE_SIG */ 0xf8, /* EVP_PKEY_CTRL_MD */ 1, 0, digestAlgorithmPtr) <= 0)
            {
                throw new Exception();
            }

            nuint written = (nuint)signature.Length;

            if (EVP_PKEY_sign(ctx, signature, ref written, hash, (IntPtr)hash.Length) <= 0)
            {
                // Crash and burn.
                throw new Exception();
            }

            if (written < 0)
            {
                throw new Exception();
            }

            if (written != (nuint)signature.Length)
            {
                //Debug.Fail($"RsaSignHash behaved unexpectedly: {nameof(written)}=={written}, {nameof(signature.Length)}=={signature.Length}");
                throw new Exception();
            }

            return signature;
        }

        /// <summary>
        /// Verifies a digest is valid given a signature.
        /// </summary>
        /// <param name="digest">The digest to validate.</param>
        /// <param name="signature">The signature to validate with.</param>
        /// <returns></returns>
        public bool VerifyDigest(byte[] digest, byte[] signature)
        {

            switch (SignatureAlgorithm)
            {
                case SigningAlgorithm.RSA:
                    using (var publicKey = Certificate.GetRSAPublicKey())
                    {
                        return publicKey.VerifyHash(digest, signature, _configuration.SignatureDigestAlgorithm, RSASignaturePadding.Pkcs1);
                    }
                case SigningAlgorithm.ECDSA:
                    using (var publicKey = Certificate.GetECDsaPublicKey())
                    {
                        return publicKey.VerifyHash(digest, signature);
                    }
                default:
                    throw new InvalidOperationException("Unknown signing algorithm.");
            }
        }
    }
}
