using Microsoft.Azure.KeyVault;
using Microsoft.Extensions.CommandLineUtils;
using OpenVsixSignTool.Core;
using System;
using System.IO;
using System.IO.Packaging;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace OpenVsixSignTool
{
    class SignCommand
    {
        internal static class EXIT_CODES
        {
            public const int SUCCESS = 0;
            public const int INVALID_OPTIONS = 1;
            public const int FAILED = 2;
        }

        private readonly CommandLineApplication _signCommandApplication;

        public SignCommand(CommandLineApplication signCommandApplication)
        {
            _signCommandApplication = signCommandApplication;
        }

        internal Task<int> SignAsync
        (
            CommandOption sha1,
            CommandOption pfxPath,
            CommandOption password,
            CommandOption timestampUrl,
            CommandOption timestampAlgorithm,
            CommandOption fileDigest,
            CommandOption force,
            CommandArgument vsixPath)
        {
            if (!(sha1.HasValue() ^ pfxPath.HasValue()))
            {
                _signCommandApplication.Out.WriteLine("Either --sha1 or --certificate must be specified, but not both.");
                _signCommandApplication.ShowHelp();
                return Task.FromResult(EXIT_CODES.INVALID_OPTIONS);
            }
            X509Certificate2 certificate;
            if (sha1.HasValue())
            {
                certificate = GetCertificateFromCertificateStore(sha1.Value());
                if (certificate == null)
                {
                    _signCommandApplication.Out.WriteLine("Unable to locate certificate by thumbprint.");
                    return Task.FromResult(EXIT_CODES.FAILED);
                }
            }
            else
            {
                var pfxFilePath = pfxPath.Value();
                if (!File.Exists(pfxFilePath))
                {
                    _signCommandApplication.Out.WriteAsync("Specified PFX file does not exist.");
                    return Task.FromResult(EXIT_CODES.INVALID_OPTIONS);
                }
                if (!password.HasValue())
                {
                    certificate = new X509Certificate2(pfxFilePath);
                }
                else
                {
                    certificate = new X509Certificate2(pfxFilePath, password.Value());
                }
            }
            Uri timestampServer = null;
            if (timestampUrl.HasValue())
            {
                if (!Uri.TryCreate(timestampUrl.Value(), UriKind.Absolute, out timestampServer))
                {
                    _signCommandApplication.Out.WriteLine("Specified timestamp URL is invalid.");
                    return Task.FromResult(EXIT_CODES.FAILED);
                }
                if (timestampServer.Scheme != Uri.UriSchemeHttp && timestampServer.Scheme != Uri.UriSchemeHttps)
                {
                    _signCommandApplication.Out.WriteLine("Specified timestamp URL is invalid.");
                    return Task.FromResult(EXIT_CODES.FAILED);
                }
            }
            var vsixPathValue = vsixPath.Value;
            if (!File.Exists(vsixPathValue))
            {
                _signCommandApplication.Out.WriteLine("Specified file does not exist.");
                return Task.FromResult(EXIT_CODES.FAILED);
            }
            HashAlgorithmName fileDigestAlgorithm, timestampDigestAlgorithm;
            var fileDigestResult = AlgorithmFromInput(fileDigest.HasValue() ? fileDigest.Value() : null);
            if (fileDigestResult == null)
            {
                _signCommandApplication.Out.WriteLine("Specified file digest algorithm is not supported.");
                return Task.FromResult(EXIT_CODES.INVALID_OPTIONS);
            }
            else
            {
                fileDigestAlgorithm = fileDigestResult.Value;
            }
            var timestampDigestResult = AlgorithmFromInput(timestampAlgorithm.HasValue() ? timestampAlgorithm.Value() : null);
            if (timestampDigestResult == null)
            {
                _signCommandApplication.Out.WriteLine("Specified timestamp digest algorithm is not supported.");
                return Task.FromResult(EXIT_CODES.INVALID_OPTIONS);
            }
            else
            {
                timestampDigestAlgorithm = timestampDigestResult.Value;
            }
            return PerformSignOnVsixAsync(vsixPathValue, force.HasValue(), timestampServer, fileDigestAlgorithm, timestampDigestAlgorithm,
                certificate, GetSigningKeyFromCertificate(certificate));
        }

        internal Task<int> SignPkcs11
        (
            CommandOption pkcs11Module,
            CommandOption pkcs11Cert,
            CommandOption pkcs11Key,
            CommandOption timestampUrl,
            CommandOption timestampAlgorithm,
            CommandOption fileDigest,
            CommandOption force,
            CommandArgument vsixPath)
        {
            if (!pkcs11Module.HasValue() || !pkcs11Cert.HasValue() || !pkcs11Key.HasValue())
            {
                _signCommandApplication.Out.WriteLine("--pkcs11-module, --pkcs11-cert and --pkcs11-key must be specified when using PKCS11 signing.");
                _signCommandApplication.ShowHelp();
                return Task.FromResult(EXIT_CODES.INVALID_OPTIONS);
            }

            Uri timestampServer = null;
            if (timestampUrl.HasValue())
            {
                if (!Uri.TryCreate(timestampUrl.Value(), UriKind.Absolute, out timestampServer))
                {
                    _signCommandApplication.Out.WriteLine("Specified timestamp URL is invalid.");
                    return Task.FromResult(EXIT_CODES.FAILED);
                }
                if (timestampServer.Scheme != Uri.UriSchemeHttp && timestampServer.Scheme != Uri.UriSchemeHttps)
                {
                    _signCommandApplication.Out.WriteLine("Specified timestamp URL is invalid.");
                    return Task.FromResult(EXIT_CODES.FAILED);
                }
            }

            var vsixPathValue = vsixPath.Value;
            if (!File.Exists(vsixPathValue))
            {
                _signCommandApplication.Out.WriteLine("Specified file does not exist.");
                return Task.FromResult(EXIT_CODES.FAILED);
            }

            HashAlgorithmName fileDigestAlgorithm, timestampDigestAlgorithm;
            var fileDigestResult = AlgorithmFromInput(fileDigest.HasValue() ? fileDigest.Value() : null);
            if (fileDigestResult == null)
            {
                _signCommandApplication.Out.WriteLine("Specified file digest algorithm is not supported.");
                return Task.FromResult(EXIT_CODES.INVALID_OPTIONS);
            }
            else
            {
                fileDigestAlgorithm = fileDigestResult.Value;
            }
            var timestampDigestResult = AlgorithmFromInput(timestampAlgorithm.HasValue() ? timestampAlgorithm.Value() : null);
            if (timestampDigestResult == null)
            {
                _signCommandApplication.Out.WriteLine("Specified timestamp digest algorithm is not supported.");
                return Task.FromResult(EXIT_CODES.INVALID_OPTIONS);
            }
            else
            {
                timestampDigestAlgorithm = timestampDigestResult.Value;
            }

            RSAOpenSsl key = GetSigningKeyFromPkcs11(pkcs11Module.Value(), pkcs11Key.Value());
            if (key == null)
            {
                _signCommandApplication.Out.WriteLine("Unable to locate key on token.");
                return Task.FromResult(EXIT_CODES.FAILED);
            }

            X509Certificate2 certificate = GetCertificateFromPkcs11(pkcs11Cert.Value());
            if (certificate == null)
            {
                _signCommandApplication.Out.WriteLine("Unable to locate certificate on token.");
                return Task.FromResult(EXIT_CODES.FAILED);
            }


            return PerformSignOnVsixAsync(vsixPathValue, force.HasValue(), timestampServer, fileDigestAlgorithm, timestampDigestAlgorithm,
                certificate, key);
        }

        internal async Task<int> SignAzure(CommandOption azureKeyVaultUrl, CommandOption azureKeyVaultClientId,
            CommandOption azureKeyVaultClientSecret, CommandOption azureKeyVaultCertificateName, CommandOption azureKeyVaultAccessToken, CommandOption force,
            CommandOption fileDigest, CommandOption timestampUrl, CommandOption timestampAlgorithm, CommandArgument vsixPath)
        {
            if (!azureKeyVaultUrl.HasValue())
            {
                _signCommandApplication.Out.WriteLine("The Azure Key Vault URL must be specified for Azure signing.");
                return EXIT_CODES.INVALID_OPTIONS;
            }


            // we only need the client id/secret if we don't have an access token
            if (!azureKeyVaultAccessToken.HasValue())
            {
                if (!azureKeyVaultClientId.HasValue())
                {
                    _signCommandApplication.Out.WriteLine("The Azure Key Vault Client ID or Access Token must be specified for Azure signing.");
                    return EXIT_CODES.INVALID_OPTIONS;
                }

                if (!azureKeyVaultClientSecret.HasValue())
                {
                    _signCommandApplication.Out.WriteLine("The Azure Key Vault Client Secret or Access Token must be specified for Azure signing.");
                    return EXIT_CODES.INVALID_OPTIONS;
                }
            }

            if (!azureKeyVaultCertificateName.HasValue())
            {
                _signCommandApplication.Out.WriteLine("The Azure Key Vault Client Certificate Name must be specified for Azure signing.");
                return EXIT_CODES.INVALID_OPTIONS;
            }
            Uri timestampServer = null;
            if (timestampUrl.HasValue())
            {
                if (!Uri.TryCreate(timestampUrl.Value(), UriKind.Absolute, out timestampServer))
                {
                    _signCommandApplication.Out.WriteLine("Specified timestamp URL is invalid.");
                    return EXIT_CODES.FAILED;
                }
                if (timestampServer.Scheme != Uri.UriSchemeHttp && timestampServer.Scheme != Uri.UriSchemeHttps)
                {
                    _signCommandApplication.Out.WriteLine("Specified timestamp URL is invalid.");
                    return EXIT_CODES.FAILED;
                }
            }
            var vsixPathValue = vsixPath.Value;
            if (!File.Exists(vsixPathValue))
            {
                _signCommandApplication.Out.WriteLine("Specified file does not exist.");
                return EXIT_CODES.FAILED;
            }
            HashAlgorithmName fileDigestAlgorithm, timestampDigestAlgorithm;
            var fileDigestResult = AlgorithmFromInput(fileDigest.HasValue() ? fileDigest.Value() : null);
            if (fileDigestResult == null)
            {
                _signCommandApplication.Out.WriteLine("Specified file digest algorithm is not supported.");
                return EXIT_CODES.INVALID_OPTIONS;
            }
            else
            {
                fileDigestAlgorithm = fileDigestResult.Value;
            }
            var timestampDigestResult = AlgorithmFromInput(timestampAlgorithm.HasValue() ? timestampAlgorithm.Value() : null);
            if (timestampDigestResult == null)
            {
                _signCommandApplication.Out.WriteLine("Specified timestamp digest algorithm is not supported.");
                return EXIT_CODES.INVALID_OPTIONS;
            }
            else
            {
                timestampDigestAlgorithm = timestampDigestResult.Value;
            }
            var configuration = new AzureKeyVaultSignConfigurationSet
            {
                AzureKeyVaultUrl = azureKeyVaultUrl.Value(),
                AzureKeyVaultCertificateName = azureKeyVaultCertificateName.Value(),
                AzureClientId = azureKeyVaultClientId.Value(),
                AzureAccessToken = azureKeyVaultAccessToken.Value(),
                AzureClientSecret = azureKeyVaultClientSecret.Value(),
            };

            var configurationDiscoverer = new KeyVaultConfigurationDiscoverer();
            var materializedResult = await configurationDiscoverer.Materialize(configuration);
            AzureKeyVaultMaterializedConfiguration materialized;
            switch (materializedResult)
            {
                case ErrorOr<AzureKeyVaultMaterializedConfiguration>.Ok ok:
                    materialized = ok.Value;
                    break;
                default:
                    _signCommandApplication.Out.WriteLine("Failed to get configuration from Azure Key Vault.");
                    return EXIT_CODES.FAILED;
            }
            var context = new KeyVaultContext(materialized.Client, materialized.KeyId, materialized.PublicCertificate);
            using (var keyVault = new RSAKeyVault(context))
            {
                return await PerformSignOnVsixAsync(
                    vsixPathValue,
                    force.HasValue(),
                    timestampServer,
                    fileDigestAlgorithm,
                    timestampDigestAlgorithm,
                    materialized.PublicCertificate,
                    keyVault
                );
            }
        }

        private async Task<int> PerformSignOnVsixAsync(string vsixPath, bool force,
            Uri timestampUri, HashAlgorithmName fileDigestAlgorithm, HashAlgorithmName timestampDigestAlgorithm,
            X509Certificate2 certificate, AsymmetricAlgorithm signingKey
            )
        {
            using (var package = OpcPackage.Open(vsixPath, OpcPackageFileMode.ReadWrite))
            {
                if (package.GetSignatures().Any() && !force)
                {
                    _signCommandApplication.Out.WriteLine("The VSIX is already signed.");
                    return EXIT_CODES.FAILED;
                }
                var signBuilder = package.CreateSignatureBuilder();
                signBuilder.EnqueueNamedPreset<VSIXSignatureBuilderPreset>();
                var signingConfiguration = new SignConfigurationSet
                (
                    fileDigestAlgorithm: fileDigestAlgorithm,
                    signatureDigestAlgorithm: fileDigestAlgorithm,
                    publicCertificate: certificate,
                    signingKey: signingKey
                );

                var signature = signBuilder.Sign(signingConfiguration);
                if (timestampUri != null)
                {
                    var timestampBuilder = signature.CreateTimestampBuilder();
                    var result = await timestampBuilder.SignAsync(timestampUri, timestampDigestAlgorithm);
                    if (result == TimestampResult.Failed)
                    {
                        return EXIT_CODES.FAILED;
                    }
                }
                _signCommandApplication.Out.WriteLine("The signing operation is complete.");
            }
            Package repack = Package.Open(vsixPath);
            repack.Flush();
            repack.Close();
            return EXIT_CODES.SUCCESS;
        }

        private static HashAlgorithmName? AlgorithmFromInput(string value)
        {
            switch (value?.ToLower())
            {
                case "sha1":
                    return HashAlgorithmName.SHA1;
                case "sha384":
                    return HashAlgorithmName.SHA384;
                case "sha512":
                    return HashAlgorithmName.SHA512;
                case null:
                case "sha256":
                    return HashAlgorithmName.SHA256;
                default:
                    return null;

            }
        }

        private static AsymmetricAlgorithm GetSigningKeyFromCertificate(X509Certificate2 certificate)
        {
            const string RSA = "1.2.840.113549.1.1.1";
            const string Ecc = "1.2.840.10045.2.1";
            var keyAlgorithm = certificate.GetKeyAlgorithm();
            switch (keyAlgorithm)
            {
                case RSA:
                    return certificate.GetRSAPrivateKey();
                case Ecc:
                    return certificate.GetECDsaPrivateKey();
                default:
                    throw new InvalidOperationException("Unknown certificate signing algorithm.");
            }
        }

        private static X509Certificate2 GetCertificateFromCertificateStore(string sha1)
        {
            using (var store = new X509Store(StoreName.My, StoreLocation.LocalMachine))
            {
                store.Open(OpenFlags.OpenExistingOnly | OpenFlags.ReadOnly);
                var certificates = store.Certificates.Find(X509FindType.FindByThumbprint, sha1, false);
                if (certificates.Count > 0)
                {
                    return certificates[0];
                }
            }

            using (var store = new X509Store(StoreName.My, StoreLocation.CurrentUser))
            {
                store.Open(OpenFlags.OpenExistingOnly | OpenFlags.ReadOnly);
                var certificates = store.Certificates.Find(X509FindType.FindByThumbprint, sha1, false);
                if (certificates.Count == 0)
                {
                    return null;
                }
                return certificates[0];
            }

        }

        [DllImport("libcrypto.so", CharSet=CharSet.Ansi)]
        private static extern IntPtr ENGINE_by_id(string engine_name);

        [DllImport("libcrypto.so", CharSet=CharSet.Ansi)]
        private static extern int ENGINE_init(IntPtr engine);

        [DllImport("libcrypto.so", CharSet=CharSet.Ansi)]
        private static extern int ENGINE_finish(IntPtr engine);

        [DllImport("libcrypto.so", CharSet=CharSet.Ansi)]
        private static extern int ENGINE_free(IntPtr engine);

        [DllImport("libcrypto.so", CharSet=CharSet.Ansi)]
        private static extern int ENGINE_ctrl_cmd(IntPtr engine, string cmd_name, long i, ref Parms p, IntPtr f, int cmd_optional);

        [DllImport("libcrypto.so", CharSet=CharSet.Ansi)]
        private static extern int ENGINE_ctrl_cmd_string(IntPtr engine, string cmd_name, string arg, int cmd_optional);

        [StructLayout(LayoutKind.Sequential)]
        private struct Parms
        {
            public string id;
            public IntPtr cert; // X509*
        }

        private X509Certificate2 GetCertificateFromPkcs11(string certName)
        {
            IntPtr engine = ENGINE_by_id("pkcs11");
            X509Certificate2 cert = null;

            if (engine != (IntPtr)0)
            {
                if (ENGINE_init(engine) != 0)
                {
                    Parms parms = new Parms { id = certName, cert = (IntPtr)0 };

                    if (ENGINE_ctrl_cmd(engine, "LOAD_CERT_CTRL", 0, ref parms, (IntPtr)0, 1) != 0) {
                        cert = new X509Certificate2(parms.cert);
                    } else {
                        _signCommandApplication.Out.WriteLine("Failed to ENGINE_ctrl_cmd");
                    }

                    ENGINE_finish(engine);
                } else {
                    _signCommandApplication.Out.WriteLine("Failed to ENGINE_init");
                }

                ENGINE_free(engine);
            } else {
                _signCommandApplication.Out.WriteLine("Failed to ENGINE_by_id");
            }

            return cert;
        }

        private RSAOpenSsl GetSigningKeyFromPkcs11(string module, string keyName)
        {
            RSAOpenSsl key = null;

            // Load openssl/engine
            try {
                SafeEvpPKeyHandle yolo = SafeEvpPKeyHandle.OpenPrivateKeyFromEngine("pkcs11", keyName);
            } catch (Exception) {}

            IntPtr engine = ENGINE_by_id("pkcs11");

            if (engine != (IntPtr)0)
            {
                if (ENGINE_init(engine) != 0)
                {
                    ENGINE_ctrl_cmd_string(engine, "MODULE_PATH", module, 0);

                    key = new RSAOpenSsl(SafeEvpPKeyHandle.OpenPrivateKeyFromEngine("pkcs11", keyName));

                    ENGINE_finish(engine);
                } else {
                    _signCommandApplication.Out.WriteLine("Failed to ENGINE_init");
                }

                ENGINE_free(engine);
            } else {
                _signCommandApplication.Out.WriteLine("Failed to ENGINE_by_id");
            }

            return key;
        }
    }
}
