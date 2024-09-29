﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Xml;

namespace OpenVsixSignTool.Core
{
    /// <summary>
    /// A builder to sign an OPC package.
    /// </summary>
    public class OpcPackageSignatureBuilder
    {
        private readonly OpcPackage _package;
        private readonly List<OpcPart> _enqueuedParts;

        internal OpcPackageSignatureBuilder(OpcPackage package)
        {
            _enqueuedParts = new List<OpcPart>();
            _package = package;
        }

        /// <summary>
        /// Enqueues a part that will be part of the package signature.
        /// </summary>
        /// <param name="part">The part to enqueue.</param>
        public void EnqueuePart(OpcPart part) => _enqueuedParts.Add(part);

        /// <summary>
        /// Dequeues a part from the signature builder. This file will not be part of the signature.
        /// </summary>
        /// <param name="part">The part to dequeue.</param>
        /// <returns>True if the file was dequeued, otherwise false.</returns>
        public bool DequeuePart(OpcPart part) => _enqueuedParts.Remove(part);

        /// <summary>
        /// Enqueues a list of parts that are known for a standard configuration.
        /// </summary>
        /// <typeparam name="TPreset">The type of preset to enqueue.</typeparam>
        public void EnqueueNamedPreset<TPreset>() where TPreset : ISignatureBuilderPreset, new()
        {
            _enqueuedParts.AddRange(new TPreset().GetPartsForSigning(_package));
        }

        /// <summary>
        /// Convert a byte array to a reverse hexadecimal string.
        /// </summary>
        /// <param name="byteArray">bytes to be converted.</param>
        private static string ByteArrayToReverseString(byte[] byteArray)
        {
            return BitConverter.ToString(byteArray.Reverse().ToArray()).Replace("-", "");
        }

        /// <summary>
        /// Creates a signature from the enqueued parts.
        /// </summary>
        /// <param name="configuration">The configuration of properties used to create the signature.
        /// See the documented of <see cref="SignConfigurationSet"/> for more information.</param>
        public OpcSignature Sign(SignConfigurationSet configuration)
        {
            var fileName = Guid.NewGuid().ToString(@"N", (IFormatProvider)null) + ".psdsxs";
            var cerName = ByteArrayToReverseString(configuration.PublicCertificate.GetSerialNumber()) + ".cer";
            var (allParts, signatureFile) = SignCore(fileName, cerName, configuration.PublicCertificate.GetRawCertData());
            var signingContext = new SigningContext(configuration);
            var (fileManifest, nodes) = OpcSignatureManifest.Build(signingContext, allParts);
            var builder = new XmlSignatureBuilder(signingContext);
            builder.SetFileManifest(fileManifest, nodes);
            var result = builder.Build();
            PublishSignature(result, signatureFile);
            _package.Flush();
            return new OpcSignature(signatureFile);
        }

        private static void PublishSignature(XmlDocument document, OpcPart signatureFile)
        {
            using (var copySignatureStream = signatureFile.Open())
            {
                copySignatureStream.SetLength(0L);
                using (var xmlWriter = new XmlTextWriter(copySignatureStream, System.Text.Encoding.UTF8))
                {
                    //The .NET implementation of OPC used by Visual Studio does not tollerate "white space" nodes.
                    xmlWriter.Formatting = Formatting.None;

                    // Create an XML declaration.
                    XmlDeclaration xmldecl;
                    xmldecl = document.CreateXmlDeclaration("1.0", null, null);
                    xmldecl.Encoding = "UTF-8";
                    xmldecl.Standalone = "yes";

                    // Add the XML declaration to the document.
                    XmlElement root = document.DocumentElement;
                    document.InsertBefore(xmldecl, root);

                    // Save document
                    document.Save(xmlWriter);
                }
            }
        }

        private (HashSet<OpcPart> partsToSign, OpcPart signaturePart) SignCore(string signatureFileName, string certificateFileName, byte[] certificateData)
        {
            var originFileUri = new Uri("package:///package/services/digital-signature/origin.psdsor", UriKind.Absolute);
            var certificateFileUriRoot = new Uri("package:///package/services/digital-signature/certificate/", UriKind.Absolute);
            var signatureUriRoot = new Uri("package:///package/services/digital-signature/xml-signature/", UriKind.Absolute);

            OpcPart originFile;
            OpcPart signatureFile;
            OpcPart certificateFile;

            // Pre-create origin part if it does not already exist.
            // Do this before signing to allow for signing the package relationship part (because a Relationship
            // is added from the Package to the Origin part by this call) and the Origin Relationship part in case this is
            // a Publishing signature and the caller wants the addition of more signatures to break this signature.
            var originFileRelationship = _package.Relationships.FirstOrDefault(r => r.Type.Equals(OpcKnownUris.DigitalSignatureOrigin));
            if (originFileRelationship != null)
            {
                originFile = _package.GetPart(originFileRelationship.Target) ?? _package.CreatePart(originFileUri, OpcKnownMimeTypes.DigitalSignatureOrigin);
            }
            else
            {
                originFile = _package.GetPart(originFileUri) ?? _package.CreatePart(originFileUri, OpcKnownMimeTypes.DigitalSignatureOrigin);
                _package.Relationships.Add(new OpcRelationship(originFile.Uri, OpcKnownUris.DigitalSignatureOrigin));
            }

            // ensure the origin relationship part is persisted so that any signature will include this newest relationship
            _package.Flush();

            var signatureRelationship = originFile.Relationships.FirstOrDefault(r => r.Type.Equals(OpcKnownUris.DigitalSignatureSignature));
            if (signatureRelationship != null)
            {
                signatureFile = _package.GetPart(signatureRelationship.Target) ?? _package.CreatePart(originFileUri, OpcKnownMimeTypes.DigitalSignatureSignature);
            }
            else
            {
                var target = new Uri(signatureUriRoot, signatureFileName);
                signatureFile = _package.GetPart(target) ?? _package.CreatePart(target, OpcKnownMimeTypes.DigitalSignatureSignature);
                originFile.Relationships.Add(new OpcRelationship(target, OpcKnownUris.DigitalSignatureSignature));
            }

            // embed certificate
            var certificateRelationship = _package.Relationships.FirstOrDefault(r => r.Type.Equals(OpcKnownUris.DigitalSignatureCertificate));
            if (certificateRelationship != null)
            {
                certificateFile = _package.GetPart(certificateRelationship.Target) ?? _package.CreatePart(originFileUri, OpcKnownMimeTypes.DigitalSignatureCertificate);
            }
            else
            {
                var target = new Uri(certificateFileUriRoot, certificateFileName);
                certificateFile = _package.GetPart(target) ?? _package.CreatePart(target, OpcKnownMimeTypes.DigitalSignatureCertificate);
                certificateFile.Open().Write(certificateData, 0, certificateData.Length);
                signatureFile.Relationships.Add(new OpcRelationship(target, OpcKnownUris.DigitalSignatureCertificate));
            }

            _package.Flush();
            var allParts = new HashSet<OpcPart>(_enqueuedParts)
            {
                _package.GetPart(_package.Relationships.DocumentUri)
            };
            return (allParts, signatureFile);
        }
    }
}
