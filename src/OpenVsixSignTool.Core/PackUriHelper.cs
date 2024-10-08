﻿//-----------------------------------------------------------------------------
//
// <copyright file="PackUriHelper.cs" company="Microsoft">
//    Copyright (C) Microsoft Corporation.  All rights reserved.
// </copyright>
//
// Description:
//  This is a helper class for pack:// Uris. This is a part of the 
//  Metro Packaging Layer
//
// History:
//  07/07/2004: SarjanaS: Initial creation. 
//  11/15/2004: SarjanaS: Adding the Compare and Normalize methods
//-----------------------------------------------------------------------------
 
// Allow use of presharp warning numbers [6506] unknown to the compiler
#pragma warning disable 1634, 1691
 
using System;
using System.IO;                        // for Path class
using System.Security;
using System.Security.Permissions;      // for Infrastructure permission
using System.Diagnostics;
using System.Windows;                   // For Exception strings - SRID
using System.Collections.Generic;       // For IEqualityComparer<>
//using MS.Internal.WindowsBase;
 
namespace OpenVsixSignTool
{
    /// <summary>
    /// This class has the utility methods for composing and parsing an Uri of pack:// scheme
    /// </summary>
    public static class PackUriHelper
    {
        //------------------------------------------------------
        //
        //  Public Constructors
        //
        //------------------------------------------------------
        // None
        //------------------------------------------------------
        //
        //  Public Properties
        //
        //------------------------------------------------------
        // None
        //------------------------------------------------------
        //
        //  Public Methods
        //
        //------------------------------------------------------

        #region Public Methods

        /// <summary>
        /// This method is used to create a valid pack Uri
        /// </summary>
        /// <param name="packageUri">This is the uri that points to the entire package.
        /// This parameter should be an absolute Uri. This parameter cannot be null or empty 
        /// This method will create a valid pack uri that references the entire package</param>
        /// <returns>A Uri with the "pack://" scheme</returns>
        /// <exception cref="ArgumentNullException">If packageUri parameter is null</exception>
        /// <exception cref="ArgumentException">If packageUri parameter is not an absolute Uri</exception>
        public static Uri Create(Uri packageUri)
        {
            return Create(packageUri, null, null);
        }

        /// <summary>
        /// This method is used to create a valid pack Uri
        /// </summary>
        /// <param name="packageUri">This is the uri that points to the entire package.
        /// This parameter should be an absolute Uri. This parameter cannot be null or empty </param>
        /// <param name="partUri">This is the uri that points to the part within the package
        /// This parameter should be a relative Uri.
        /// This parameter can be null in which case we will create a valid pack uri
        /// that references the entire package</param>
        /// <returns>A Uri with the "pack://" scheme</returns>
        /// <exception cref="ArgumentNullException">If packageUri parameter is null</exception>
        /// <exception cref="ArgumentException">If packageUri parameter is not an absolute Uri</exception>
        /// <exception cref="ArgumentException">If partUri parameter does not conform to the valid partUri syntax</exception>
        public static Uri Create(Uri packageUri, Uri partUri)
        {
            return Create(packageUri, partUri, null);
        }

        /// <summary>
        /// This method is used to create a valid pack Uri
        /// </summary>
        /// <param name="packageUri">This is the uri that points to the entire package.
        /// This parameter should be an absolute Uri. This parameter cannot be null or empty </param>
        /// <param name="partUri">This is the uri that points to the part within the package
        /// This parameter should be a relative Uri.
        /// This parameter can be null in which case we will create a valid pack uri
        /// that references the entire package</param>
        /// <param name="fragment">Fragment for the resulting Pack URI. This parameter can be null
        /// The fragment string must start with a "#"</param>
        /// <returns>A Uri with the "pack://" scheme</returns>
        /// <exception cref="ArgumentNullException">If packageUri parameter is null</exception>
        /// <exception cref="ArgumentException">If packageUri parameter is not an absolute Uri</exception>
        /// <exception cref="ArgumentException">If partUri parameter does not conform to the valid partUri syntax</exception>
        /// <exception cref="ArgumentException">If fragment parameter is empty or does not start with a "#"</exception>
        public static Uri Create(Uri packageUri, Uri partUri, string fragment)
        {
            // Step 1 - Validate input parameters
            packageUri = ValidatePackageUri(packageUri);

            if (partUri != null)
                partUri = ValidatePartUri(partUri);

            if (fragment != null)
            {
                if (fragment == String.Empty || fragment[0] != '#')
                    throw new ArgumentException("error");
            }

            // Step 2 - Remove fragment identifier from the package URI, if it is present
            // Since '#" is an excluded character in Uri syntax, it can only occur as the 
            // fragment identifier, in all other places it should be escaped.
            // Hence we can safely use IndexOf to find the begining of the fragment.
            string absolutePackageUri = packageUri.GetComponents(UriComponents.AbsoluteUri, UriFormat.UriEscaped);

            //PRESHARP:Warning 6506 Parameter to this public method must be validated:  A null-dereference can occur here.
            //We know that the Fragment property will always be a string and never will return null, String.Empty if the fragment is empty.
#pragma warning disable 6506
            if (packageUri.Fragment.Length != 0)
#pragma warning restore 6506
            {
                absolutePackageUri = absolutePackageUri.Substring(0, absolutePackageUri.IndexOf('#'));
            }

            // Step 3 - Escape: "%", "?", "@", "#" and "," in the package URI 
            absolutePackageUri = EscapeSpecialCharacters(absolutePackageUri);

            // Step 4 - Replace all '/' with ',' in the resulting string
            absolutePackageUri = absolutePackageUri.Replace('/', ',');

            // Step 5 - Append pack:// at the begining and a '/' at the end of the pack uri obtained so far            
            absolutePackageUri = String.Concat(PackUriHelper.UriSchemePack, Uri.SchemeDelimiter, absolutePackageUri);

            Uri packUri = new Uri(absolutePackageUri);

            // Step 6 - Append the part Uri if present.
            if (partUri != null)
                packUri = new Uri(packUri, partUri);

            // Step 7 - Append fragment if present
            if (fragment != null)
                packUri = new Uri(String.Concat(packUri.GetComponents(UriComponents.AbsoluteUri, UriFormat.UriEscaped), fragment));

            // We want to ensure that internal content of resulting Uri has canonical form
            // i.e.  result.OrignalString would appear as perfectly formatted Uri string 
            // so we roundtrip the result.

            return new Uri(packUri.GetComponents(UriComponents.AbsoluteUri, UriFormat.UriEscaped));
        }

        /// <summary>
        /// This method parses the pack uri and returns the inner
        /// Uri that points to the package as a whole.
        /// </summary>
        /// <param name="packUri">Uri which has pack:// scheme</param>
        /// <returns>Returns the inner uri that points to the entire package</returns>
        /// <exception cref="ArgumentNullException">If packUri parameter is null</exception>
        /// <exception cref="ArgumentException">If packUri parameter is not an absolute Uri</exception>
        /// <exception cref="ArgumentException">If packUri parameter does not have "pack://" scheme</exception>
        /// <exception cref="ArgumentException">If inner packageUri extracted from the packUri has a fragment component</exception>
        public static Uri GetPackageUri(Uri packUri)
        {
            Uri packageUri;
            Uri partUri;

            //Parameter Validation is done in the follwoing method
            ValidateAndGetPackUriComponents(packUri, out packageUri, out partUri);

            return packageUri;
        }

        /// <summary>
        /// This method parses the pack uri and returns the absolute 
        /// path of the URI. This corresponds to the part within the 
        /// package. This corresponds to the absolute path component in 
        /// the Uri. If there is no part component present, this method
        /// returns a null
        /// </summary>
        /// <param name="packUri">Returns a relative Uri that represents the
        /// part within the package. If the pack Uri points to the entire
        /// package then we return a null</param>
        /// <returns>Returns a relative URI with an absolute path that points to a part within a package</returns>
        /// <exception cref="ArgumentNullException">If packUri parameter is null</exception>
        /// <exception cref="ArgumentException">If packUri parameter is not an absolute Uri</exception>
        /// <exception cref="ArgumentException">If packUri parameter does not have "pack://" scheme</exception>
        /// <exception cref="ArgumentException">If partUri extracted from packUri does not conform to the valid partUri syntax</exception>
        public static Uri GetPartUri(Uri packUri)
        {
            Uri packageUri;
            Uri partUri;

            //Parameter Validation is done in the follwoing method
            ValidateAndGetPackUriComponents(packUri, out packageUri, out partUri);

            return partUri;
        }

        /// <summary>
        /// This method is used to create a valid part Uri given a relative URI
        /// Makes sure that the URI -  
        /// 1. Relative 
        /// 2. Begins with '/'
        /// 3. Does not begin with two "//"
        /// 4. Does not end with "/"
        /// 5. Does not have a fragment component
        /// 6. Does the correct escaping 
        /// 7. And is refined correctly
        /// </summary>
        /// <param name="partUri">The relative uri that represents the part within a package</param>
        /// <returns>Returns a relative URI with an absolute path that points to a part within a package</returns>
        /// <exception cref="ArgumentNullException">If partUri parameter is null</exception>
        /// <exception cref="ArgumentException">If partUri parameter is an absolute Uri</exception>
        /// <exception cref="ArgumentException">If partUri parameter is empty</exception>
        /// <exception cref="ArgumentException">If partUri parameter ends with "/"</exception>
        /// <exception cref="ArgumentException">If partUri parameter starts with two "/"</exception>
        /// <exception cref="ArgumentException">If partUri parameter has a fragment</exception>
        public static Uri CreatePartUri(Uri partUri)
        {
            if (partUri == null)
                throw new ArgumentNullException("partUri");

            ThrowIfAbsoluteUri(partUri);

            string serializedPartUri = partUri.GetComponents(UriComponents.SerializationInfoString, UriFormat.SafeUnescaped);
            ThrowIfPartNameStartsWithTwoSlashes(serializedPartUri);
            ThrowIfFragmentPresent(serializedPartUri);

            //Create an absolute URI to get the refinement on the relative URI
            Uri resolvedUri = new Uri(_defaultUri, partUri);

            string partName = GetStringForPartUriFromAnyUri(resolvedUri);

            if (partName == String.Empty)
                throw new ArgumentException("error");

            ThrowIfPartNameEndsWithSlash(partName);

            return new ValidatedPartUri(partName);
        }

        /// <summary>
        /// This method is used to resolve part Uris
        /// Constructs resolved relative URI from two relative URIs
        /// This method should be used in places where we have a 
        /// a target URI in the PackageRelationship and we want to get the 
        /// name of the part it targets with respect to the source part
        /// </summary>
        /// <param name="sourcePartUri">This should be a valid partName. 
        /// The only exception to this rule is an Uri of the form "/". This uri 
        /// will only be used to resolve package level relationships. This Uri
        /// indicates that the relative Uri is being resolved against the root of the
        /// package.</param>
        /// <param name="targetUri">This URI can be any relative URI</param>
        /// <returns></returns>
        /// <exception cref="ArgumentNullException">If either sourcePartUri or targetUri parameter is null</exception>
        /// <exception cref="ArgumentException">If either sourcePartUri or targetUri parameter is an absolute Uri</exception>
        /// <exception cref="ArgumentException">If sourcePartUri parameter does not conform to the valid partUri syntax</exception>
        public static Uri ResolvePartUri(Uri sourcePartUri, Uri targetUri)
        {
            if (sourcePartUri == null)
                throw new ArgumentNullException("sourcePartUri");

            if (targetUri == null)
                throw new ArgumentNullException("targetUri");

            ThrowIfAbsoluteUri(sourcePartUri);

            ThrowIfAbsoluteUri(targetUri);

            Uri resolvedUri;

            if (sourcePartUri == PackageRootUri)
                resolvedUri = new Uri(_defaultUri, targetUri);
            else
                resolvedUri = new Uri(new Uri(_defaultUri, ValidatePartUri(sourcePartUri)), targetUri);

            return new Uri(resolvedUri.AbsolutePath, UriKind.Relative);
        }

        /// <summary>
        /// This method returns the relative uri between two given parts
        /// </summary>
        /// <param name="sourcePartUri"></param>
        /// <param name="targetPartUri"></param>
        /// <returns>The relative path between two parts</returns>
        /// <exception cref="ArgumentNullException">If either the sourcePartUri or targetPartUri parameter is null</exception>
        /// <exception cref="ArgumentException">If either sourcePartUri or targetPartUri parameter does not conform to the valid partUri syntax</exception>
        public static Uri GetRelativeUri(Uri sourcePartUri, Uri targetPartUri)
        {
            //although we do expect the subsequent ValidatePartUri call to throw in case of null 
            // as well, it dosn't have the right parameter namer for ValidatePartUri function 
            if (sourcePartUri == null)
                throw new ArgumentNullException("sourcePartUri");

            if (targetPartUri == null)
                throw new ArgumentNullException("targetPartUri");

            sourcePartUri = new Uri(_defaultUri, ValidatePartUri(sourcePartUri));
            targetPartUri = new Uri(_defaultUri, ValidatePartUri(targetPartUri));

            return sourcePartUri.MakeRelativeUri(targetPartUri);
        }

        /// <summary>
        /// Returns the normalized form of the part URI
        /// </summary>
        /// <param name="partUri">Part Uri</param>
        /// <returns>Normalized Part Uri</returns>
        /// <exception cref="ArgumentNullException">If partUri is null</exception>
        /// <exception cref="ArgumentException">If partUri parameter does not conform to the valid partUri syntax</exception>
        public static Uri GetNormalizedPartUri(Uri partUri)
        {
            if (partUri == null)
                throw new ArgumentNullException("partUri");

            if (!(partUri is ValidatedPartUri))
                partUri = ValidatePartUri(partUri);
            return ((ValidatedPartUri)partUri).NormalizedPartUri;
        }

        /// <summary>
        /// This method compares two pack uris and returns an int to indicate the equivalence. 
        /// </summary>
        /// <param name="firstPackUri">First Uri of pack:// scheme to be compared</param>
        /// <param name="secondPackUri">Second Uri of pack:// scheme to be compared</param>
        /// <returns>A 32-bit signed integer indicating the lexical relationship between the compared Uri components.
        /// Value - Less than zero means firstUri is less than secondUri
        /// Value - Equal to zero means both the Uris are equal
        /// Value - Greater than zero means firstUri is greater than secondUri </returns>
        /// <exception cref="ArgumentException">If either of the Uris are not absolute or if either of the Uris are not with pack:// scheme</exception>
        /// <exception cref="ArgumentException">If firstPackUri or secondPackUri parameter is not an absolute Uri</exception>
        /// <exception cref="ArgumentException">If firstPackUri or secondPackUri parameter does not have "pack://" scheme</exception>
        public static int ComparePackUri(Uri firstPackUri, Uri secondPackUri)
        {
            //If any of the operands are null then we simply call System.Uri compare to return the correct value
            if (firstPackUri == null || secondPackUri == null)
                return CompareUsingSystemUri(firstPackUri, secondPackUri);
            else
            {
                int compareResult;

                Uri firstPackageUri;
                Uri secondPackageUri;
                Uri firstPartUri;
                Uri secondPartUri;

                ValidateAndGetPackUriComponents(firstPackUri, out firstPackageUri, out firstPartUri);
                ValidateAndGetPackUriComponents(secondPackUri, out secondPackageUri, out secondPartUri);


                if (firstPackageUri.Scheme == PackUriHelper.UriSchemePack && secondPackageUri.Scheme == PackUriHelper.UriSchemePack)
                {
                    compareResult = ComparePackUri(firstPackageUri, secondPackageUri);
                }
                else
                {
                    compareResult = CompareUsingSystemUri(firstPackageUri, secondPackageUri);
                }

                //Iff the PackageUri match do we compare the part uris.
                if (compareResult == 0)
                {
                    compareResult = ComparePartUri(firstPartUri, secondPartUri);
                }

                return compareResult;
            }
        }

        /// <summary>
        /// This method compares two part uris and returns an int to indicate the equivalence
        /// Null values are allowed
        /// </summary>
        /// <param name="firstPartUri">First part Uri to be compared</param>
        /// <param name="secondPartUri">Second part Uri to be compared</param>
        /// <returns>A 32-bit signed integer indicating the lexical relationship between the compared Uri components.
        /// Value - Less than zero means firstUri is less than secondUri
        /// Value - Equal to zero means both the Uris are equal</returns>
        /// Value - Greater than zero means firstUri is greater than secondUri
        /// <exception cref="ArgumentException">If firstPartUri or secondPartUri parameter does not conform to the valid partUri syntax</exception>
        public static int ComparePartUri(Uri firstPartUri, Uri secondPartUri)
        {
            if (firstPartUri != null)
                firstPartUri = ValidatePartUri(firstPartUri);

            if (secondPartUri != null)
                secondPartUri = ValidatePartUri(secondPartUri);

            //If any of the operands are null then we simply call System.Uri compare to return the correct value
            if (firstPartUri == null || secondPartUri == null)
                return CompareUsingSystemUri(firstPartUri, secondPartUri);

            return ((IComparable<ValidatedPartUri>)firstPartUri).CompareTo((ValidatedPartUri)secondPartUri);
        }

        /// <summary>
        /// IsRelationshipPartUri method returns a boolean indicating whether the
        /// Uri given is a relationship part Uri or not.
        /// </summary>
        /// <param name="partUri">uri of part to evaluate</param>
        /// <returns>true if the given part is a PackageRelationship part</returns>
        /// <remarks>Does not inspect the part contents - this is based solely on the name</remarks>
        /// <exception cref="ArgumentNullException">If partUri parameter is null</exception>
        /// <exception cref="ArgumentException">If partUri parameter is an absolute Uri</exception>
        /// <exception cref="ArgumentException">If partUri parameter does not conform to the valid partUri Syntax</exception>
        public static bool IsRelationshipPartUri(Uri partUri)
        {
            if (partUri == null)
                throw new ArgumentNullException("partUri");

            if (!(partUri is ValidatedPartUri))
                partUri = ValidatePartUri(partUri);

            return ((ValidatedPartUri)partUri).IsRelationshipPartUri;
        }
        private static readonly Uri _containerRelationshipPartName = PackUriHelper.CreatePartUri(new Uri("/_rels/.rels", UriKind.Relative));

        /// <summary>
        /// This method returns a relationship part Uri given a part Uri
        /// Example Input - partUri - /files/document.xaml
        /// Return  - Relationship Uri  - /files/_rels/document.xaml.rels
        /// If the input to the method is Uri - "/", then we will return /_rels/.rels as the
        /// relationship part Uri for the Package level relationships
        /// </summary>
        /// <param name="partUri">Part Uri for which the relationship part Uri is wanted</param>
        /// <returns>returns a Uri that conforms to the relationship part Uri syntax</returns>
        /// <exception cref="ArgumentException">If the input Uri is a relationship part Uri itself</exception>
        /// <exception cref="ArgumentNullException">If partUri parameter is null</exception>
        /// <exception cref="ArgumentException">If partUri parameter is an absolute Uri</exception>
        /// <exception cref="ArgumentException">If partUri parameter does not conform to the valid partUri Syntax</exception>
        public static Uri GetRelationshipPartUri(Uri partUri)
        {
            if (partUri == null)
                throw new ArgumentNullException("partUri");

            if (Uri.Compare(partUri, PackageRootUri, UriComponents.SerializationInfoString, UriFormat.UriEscaped, StringComparison.Ordinal) == 0)
                return _containerRelationshipPartName;

            // Verify  -
            // 1. Validates that this part Uri is a valid part Uri

            partUri = ValidatePartUri(partUri);

            // 2. Checks that this part Uri is not a relationshipPart Uri
            if (IsRelationshipPartUri(partUri))
                throw new ArgumentException("error");

            //We should have a ValidatedPartUri by this time
            string partName = ((ValidatedPartUri)partUri).PartUriString;

            string file = Path.GetFileName(partName);

            Debug.Assert((partName.Length - file.Length) > 0,
                "The partname may not be wellformed");

            // Get the parname without the last segment
            partName = partName.Substring(0, partName.Length - file.Length);

            partName = Path.Combine(partName, _relationshipPartSegmentName);         // Adding the "_rels" segment
            partName = Path.Combine(partName, file);                                 // Adding the last segment back
            partName = String.Concat(partName, _relationshipPartExtensionName);      // Adding the ".rels" extension
            partName = partName.Replace(BackwardSlashChar, ForwardSlashChar);

            // convert to Uri - We could use PackUriHelper.Create, but since we know that this is a
            //valid Part Uri we can just call the Uri constructor.
            return new ValidatedPartUri(partName, true /*IsRelationship*/);
        }


        /// <summary>
        /// Given a valid relationship Part Uri, this method returns the source Part Uri for 
        /// this relationship Part Uri. 
        /// If the relationship part name is for the Package Level relationships [/_rels/.rels],
        /// we return a relative Uri of the form "/" indicating that it has no part as the parent, 
        /// but is at the package level
        /// Example Input - Relationship Uri  - /files/_rels/document.xaml.rels
        /// Returns -Source Part Uri - /files/document.xaml
        /// </summary>
        /// <param name="relationshipPartUri">relationship part Uri</param>
        /// <returns>A uri that is a valid source part Uri for the relationship Uri provided</returns>
        /// <exception cref="ArgumentNullException">If relationshipPartUri parameter is null</exception>
        /// <exception cref="ArgumentException">If relationshipPartUri parameter is an absolute Uri</exception>
        /// <exception cref="ArgumentException">If relationshipPartUri parameter does not conform to the valid partUri Syntax</exception>
        /// <exception cref="ArgumentException">If the relationshipPartUri is not a relationship part Uri itself</exception>
        /// <exception cref="ArgumentException">If the resultant Uri obtained is a relationship part Uri</exception>
        public static Uri GetSourcePartUriFromRelationshipPartUri(Uri relationshipPartUri)
        {
            if (relationshipPartUri == null)
                throw new ArgumentNullException("relationshipPartUri");

            // Verify -
            // 1. Validates that this part Uri is a valid part Uri
            relationshipPartUri = ValidatePartUri(relationshipPartUri);

            // 2. Checks that this part Uri is not a relationshipPart Uri
            if (!IsRelationshipPartUri(relationshipPartUri))
                throw new ArgumentException("error");

            // _rels/.rels has no parent part
            if (PackUriHelper.ComparePartUri(_containerRelationshipPartName, relationshipPartUri) == 0)
            {
                return PackageRootUri;
            }
            else
            {
                //We should have a ValidatedPartUri by this time
                string path = ((ValidatedPartUri)relationshipPartUri).PartUriString;

                string partNameWithoutExtension = Path.GetFileNameWithoutExtension(path);

                Debug.Assert((path.Length - partNameWithoutExtension.Length - _relationshipPartExtensionName.Length - 1) > 0,
                    "The partname may not be wellformed");

                //Get the part name without the last segment
                path = path.Substring(0, path.Length - partNameWithoutExtension.Length - _relationshipPartExtensionName.Length - 1);

                Debug.Assert((path.Length - _relationshipPartSegmentName.Length) > 0,
                    "The partname may not be wellformed");

                path = path.Substring(0, path.Length - _relationshipPartSegmentName.Length); // Removing rels segment
                path = Path.Combine(path, partNameWithoutExtension);        // Adding the last segment without ".rels" extension
                path = path.Replace(BackwardSlashChar, ForwardSlashChar);

                // convert to Uri - We could use PackUriHelper.Create, but since we know that this is a
                //valid Part Uri we can just call the Uri constructor.            
                return new ValidatedPartUri(path, false /*IsRelationship*/);
            }
        }

        #endregion Public Methods

        //------------------------------------------------------
        //
        //  Public Events
        //
        //------------------------------------------------------
        // None
        //------------------------------------------------------
        //
        //  Internal Constructors
        //
        //------------------------------------------------------
        // None
        //------------------------------------------------------
        //
        //  Internal Properties
        //
        //------------------------------------------------------

        #region Internal Properties

        internal static Uri PackageRootUri
        {
            get
            {
                return _packageRootUri;
            }
        }

        #endregion Internal Properties

        //------------------------------------------------------
        //
        //  Internal Methods
        //
        //------------------------------------------------------

        #region Internal Methods

        internal static bool IsPackUri(Uri uri)
        {
            return uri != null &&
                string.Compare(uri.Scheme, UriSchemePack, StringComparison.OrdinalIgnoreCase) == 0;
        }

        internal static bool TryValidatePartUri(Uri partUri, out ValidatedPartUri validatedPartUri)
        {
            if (partUri is ValidatedPartUri)
            {
                validatedPartUri = (ValidatedPartUri)partUri;
                return true;
            }
            else
            {
                string partUriString;
                Exception exception = GetExceptionIfPartUriInvalid(partUri, out partUriString);
                if (exception != null)
                {
                    validatedPartUri = null;
                    return false;
                }
                else
                {
                    validatedPartUri = new ValidatedPartUri(partUriString);
                    return true;
                }
            }
        }

        /// <summary>
        /// This method is used to validate a part Uri
        /// This method does not perform a case sensitive check of the Uri
        /// </summary>
        /// <param name="partUri">The string that represents the part within a package</param>
        /// <returns>Returns the part uri if it is valid</returns>
        /// <exception cref="ArgumentNullException">If partUri parameter is null</exception>
        /// <exception cref="ArgumentException">If partUri parameter is an absolute Uri</exception>
        /// <exception cref="ArgumentException">If partUri parameter is empty</exception>
        /// <exception cref="ArgumentException">If partUri parameter does not start with a "/"</exception>
        /// <exception cref="ArgumentException">If partUri parameter starts with two "/"</exception>
        /// <exception cref="ArgumentException">If partUri parameter ends with a "/"</exception>
        /// <exception cref="ArgumentException">If partUri parameter has a fragment</exception>
        /// <exception cref="ArgumentException">If partUri parameter has some escaped characters that should not be escaped
        /// or some characters that should be escaped are not escaped.</exception>
        internal static ValidatedPartUri ValidatePartUri(Uri partUri)
        {
            if (partUri is ValidatedPartUri)
                return (ValidatedPartUri)partUri;

            string partUriString;
            Exception exception = GetExceptionIfPartUriInvalid(partUri, out partUriString);
            if (exception != null)
            {
                Debug.Assert(partUriString != null && partUriString.Length == 0);
                throw exception;
            }
            else
            {
                Debug.Assert(partUriString != null && partUriString.Length > 0);
                return new ValidatedPartUri(partUriString);
            }
        }

        //Returns the part name in its escaped string form.
        internal static string GetStringForPartUri(Uri partUri)
        {
            Debug.Assert(partUri != null, "Null reference check for this uri parameter should have been made earlier");
            if (!(partUri is ValidatedPartUri))
                partUri = ValidatePartUri(partUri);

            return ((ValidatedPartUri)partUri).PartUriString;
        }

        //This method validates the packUri and returns its two components if they are valid-
        //1. Package Uri
        //2. Part Uri
        internal static void ValidateAndGetPackUriComponents(Uri packUri, out Uri packageUri, out Uri partUri)
        {
            //Validate if its not null and is an absolute Uri, has pack:// Scheme.
            packUri = ValidatePackUri(packUri);
            packageUri = GetPackageUriComponent(packUri);
            partUri = GetPartUriComponent(packUri);
        }

        #endregion Internal Methods

        //------------------------------------------------------
        //
        //  Internal Events
        //
        //------------------------------------------------------
        // None
        //------------------------------------------------------
        //
        //  Private Constructors
        //
        //------------------------------------------------------

        #region Private Constructor

        // <SecurityNote>
        //   Critical    - as this code does an elevation
        //   TreatAsSafe - the net effect of this is to enable registration of Pack: Uri scheme. 
        //   This enables fetching of resources via this scheme. Considered safe - as currently 
        //   the pack: scheme has no elevations in it ( and any necessary elevations for container 
        //   access will be reviewed as needed). 
        // </SecurityNote>         
        [SecurityTreatAsSafe, SecurityCritical]
        static PackUriHelper()
        {
            // indicate that we want "basic" parsing
            if (!UriParser.IsKnownScheme(UriSchemePack))
            {
                try
                {
                    SecurityPermission permobj = new SecurityPermission(SecurityPermissionFlag.Infrastructure);
                    permobj.Assert(); //BlessedAssert:

                    // Indicate that we want a default hierarchical parser with a registry based authority
                    UriParser.Register(new GenericUriParser(GenericUriParserOptions.GenericAuthority), UriSchemePack, -1);
                }
                finally
                {
                    SecurityPermission.RevertAssert();
                }
            }
        }

        #endregion Private Constructor

        //------------------------------------------------------
        //
        //  Private Methods
        //
        //------------------------------------------------------

        #region Private Methods

        /// <summary>
        /// This method is used to validate the package uri
        /// </summary>
        /// <param name="packageUri"></param>
        /// <returns></returns>
        private static Uri ValidatePackageUri(Uri packageUri)
        {
            if (packageUri == null)
                throw new ArgumentNullException("packageUri");

            if (!packageUri.IsAbsoluteUri)
                throw new ArgumentException("error");

            return packageUri;
        }

        //validates is a given uri has pack:// scheme
        private static Uri ValidatePackUri(Uri packUri)
        {
            if (packUri == null)
                throw new ArgumentNullException("packUri");

            if (!packUri.IsAbsoluteUri)
                throw new ArgumentException("error");

            if (packUri.Scheme != PackUriHelper.UriSchemePack)
                throw new ArgumentException("error");

            return packUri;

        }

        /// <summary>
        /// Escapes -  %', '@', ',', '?' in the package URI 
        /// This method modifies the string in a culture safe and case safe manner. 
        /// </summary>
        /// <param name="path"></param>
        /// <returns></returns>
        private static string EscapeSpecialCharacters(string path)
        {
            string characterString;

            // Escaping for the following - '%'; '@'; ',' and '?'
            // !!Important!! - The order is important - The '%' sign should be escaped first.
            // This is currently enforced by the order of characters in the _specialCharacters array
            foreach (char c in _specialCharacters)
            {
                characterString = c.ToString();
                if (path.Contains(characterString))
                    path = path.Replace(characterString, Uri.HexEscape(c));
            }

            return path;
        }

        private static Exception GetExceptionIfPartUriInvalid(Uri partUri, out string partUriString)
        {
            partUriString = String.Empty;

            if (partUri == null)
                return new ArgumentNullException("partUri");

            Exception argumentException = null;

            argumentException = GetExceptionIfAbsoluteUri(partUri);
            if (argumentException != null)
                return argumentException;

            string partName = GetStringForPartUriFromAnyUri(partUri);

            //We need to make sure that the URI passed to us is not just "/"
            //"/" is a valid relative uri, but is not a valid partname
            if (partName == String.Empty)
                return new ArgumentException("error");

            if (partName[0] != '/')
                return new ArgumentException("error");

            argumentException = GetExceptionIfPartNameStartsWithTwoSlashes(partName);
            if (argumentException != null)
                return argumentException;

            argumentException = GetExceptionIfPartNameEndsWithSlash(partName);
            if (argumentException != null)
                return argumentException;

            argumentException = GetExceptionIfFragmentPresent(partName);
            if (argumentException != null)
                return argumentException;

            //We test if the URI is wellformed and refined.
            //The relative URI that was passed to us may not be correctly escaped and so we test that.
            //Also there might be navigation "/../" present in the URI which we need to detect.
            string wellFormedPartName =
                new Uri(_defaultUri, partName).GetComponents(UriComponents.Path |
                                                             UriComponents.KeepDelimiter, UriFormat.UriEscaped);

            //Note - For Relative Uris the output of ToString() and OriginalString property 
            //are the same as per the current implementation of System.Uri
            //Need to use OriginalString property or ToString() here as we are want to 
            //validate that the input uri given to us was valid in the first place.
            //We do not want to use GetComponents in this case as it might lead to
            //performing escaping or unescaping as per the UriFormat enum value and that 
            //may alter the string that the user created the Uri with and we may not be able 
            //to verify the uri correctly.
            //We perform the comparison in a case-insensitive manner, as at this point,
            //only escaped hex digits (A-F) might vary in casing.
            if (String.CompareOrdinal(partUri.OriginalString.ToUpperInvariant(), wellFormedPartName.ToUpperInvariant()) != 0)
                return new ArgumentException("error");

            //if we get here, the partUri is valid and so we return null, as there is no exception.
            partUriString = partName;
            return null;
        }

        private static void ThrowIfAbsoluteUri(Uri uri)
        {
            Exception exception = GetExceptionIfAbsoluteUri(uri);
            if (exception != null)
                throw exception;
        }

        private static ArgumentException GetExceptionIfAbsoluteUri(Uri uri)
        {
            if (uri.IsAbsoluteUri)
                return new ArgumentException("error");
            else
                return null;
        }

        private static void ThrowIfFragmentPresent(string partName)
        {
            Exception exception = GetExceptionIfFragmentPresent(partName);
            if (exception != null)
                throw exception;
        }

        private static ArgumentException GetExceptionIfFragmentPresent(string partName)
        {
            if (partName.Contains("#"))
                return new ArgumentException("error");
            else
                return null;
        }

        private static void ThrowIfPartNameEndsWithSlash(string partName)
        {
            Exception exception = GetExceptionIfPartNameEndsWithSlash(partName);
            if (exception != null)
                throw exception;
        }

        private static ArgumentException GetExceptionIfPartNameEndsWithSlash(string partName)
        {
            if (partName.Length > 0)
            {
                if (partName[partName.Length - 1] == '/')
                    return new ArgumentException("error");
            }
            return null;
        }

        private static void ThrowIfPartNameStartsWithTwoSlashes(string partName)
        {
            Exception exception = GetExceptionIfPartNameStartsWithTwoSlashes(partName);
            if (exception != null)
                throw exception;
        }

        // A relative reference that begins with two slash characters is termed
        // a network-path reference; such references are rarely used. 
        // However, when they are resolved they represent the authority part of the URI
        // Absolute URI - `http://a/b/c/d;p?q
        // Relative URI - //m
        // Resolved URI - `http://m
        private static ArgumentException GetExceptionIfPartNameStartsWithTwoSlashes(string partName)
        {
            if (partName.Length > 1)
            {
                if (partName[0] == '/' && partName[1] == '/')
                    return new ArgumentException("error");
            }
            return null;
        }

        //Calling System.Uri.Compare method
        //This method minimizes the false positives that we might get as a result
        //of comparing two URIs.
        //Also, we exclude the Fragment component while comparing.
        private static int CompareUsingSystemUri(Uri firstUri, Uri secondUri)
        {
            return Uri.Compare(
                    firstUri,
                    secondUri,
                    UriComponents.AbsoluteUri & ~UriComponents.Fragment,
                    UriFormat.UriEscaped,
                    StringComparison.Ordinal);
        }

        //Returns the part name in its escaped string form from an Absolute [must be pack://] or a Relative URI
        private static string GetStringForPartUriFromAnyUri(Uri partUri)
        {
            Debug.Assert(partUri != null, "Null reference check for this uri parameter should have been made earlier");
            Debug.Assert(!(partUri is ValidatedPartUri), "This method should only be called when we have not already validated the part uri");

            Uri safeUnescapedUri;

            // Step 1: Get the safe-unescaped form of the URI first. This will unescape all the characters
            // that can be safely un-escaped, unreserved characters, unicode characters, etc.
            if (!partUri.IsAbsoluteUri)
            {
                //We assume a well formed part uri has been passed to this method
                safeUnescapedUri = new Uri(partUri.GetComponents(UriComponents.SerializationInfoString, UriFormat.SafeUnescaped), UriKind.Relative);
            }
            else
            {
                safeUnescapedUri =
                    new Uri(partUri.GetComponents(UriComponents.Path |
                                                  UriComponents.KeepDelimiter, UriFormat.SafeUnescaped), UriKind.Relative);
            }

            // Step 2: Get the canonically escaped Path with only ascii characters
            //Get the escaped string for the part name as part names should have only ascii characters
            String partName = safeUnescapedUri.GetComponents(UriComponents.SerializationInfoString, UriFormat.UriEscaped);

            //The part name can be empty in cases where we were passed a pack URI that has no part component
            if (IsPartNameEmpty(partName))
                return String.Empty;
            else
                return partName;
        }

        //Verifies whether the part name is empty. PartName can be empty in two cases :
        //1. Empty String
        //2. String with just the begining "/"
        private static bool IsPartNameEmpty(string partName)
        {
            Debug.Assert(partName != null, "Null reference check for this partName parameter should have been made earlier");

            // Uri.GetComponents may return a single forward slash when there is no absolute path.  
            // This is Whidbey PS399695.  Until that is changed, we check for both cases - either an entirely empty string,
            // or a single forward slash character.  Either case means there is no part name.
            if (partName.Length == 0 || ((partName.Length == 1) && (partName[0] == '/')))
                return true;
            else
                return false;

        }

        //This method validates and returns the PackageUri component
        private static Uri GetPackageUriComponent(Uri packUri)
        {
            Debug.Assert(packUri != null, "packUri parameter cannot be null");

            //Step 1 - Get the authority part of the URI. This section represents that package URI
            String hostAndPort = packUri.GetComponents(UriComponents.HostAndPort, UriFormat.UriEscaped);

            //Step 2 - Replace the ',' with '/' to reconstruct the package URI
            hostAndPort = hostAndPort.Replace(',', '/');

            //Step 3 - Unescape the special characters that we had escaped to construct the packUri
            Uri packageUri = new Uri(Uri.UnescapeDataString(hostAndPort));

            if (packageUri.Fragment != String.Empty)
                throw new ArgumentException("error");

            return packageUri;
        }

        //This method validates and returns the PartUri component.
        private static PackUriHelper.ValidatedPartUri GetPartUriComponent(Uri packUri)
        {
            Debug.Assert(packUri != null, "packUri parameter cannot be null");

            string partName = GetStringForPartUriFromAnyUri(packUri);

            if (partName == String.Empty)
                return null;
            else
                return ValidatePartUri(new Uri(partName, UriKind.Relative));
        }

        #endregion Private Methods

        //------------------------------------------------------
        //
        //  Private Fields
        //
        //------------------------------------------------------

        #region Private Members

        //we use this dummy URI to resolve relative URIs treating the container as the authority.
        private static readonly Uri _defaultUri = new Uri("http://defaultcontainer/");

        //we use this dummy Uri to represent the root of the container.
        private static readonly Uri _packageRootUri = new Uri("/", UriKind.Relative);

        // We need to perform Escaping for the following - '%'; '@'; ',' and '?' 
        // !!Important!! - The order is important - The '%' sign should be escaped first.
        // If any more characters need to be added to the array below they should be added at the end.
        private static readonly char[] _specialCharacters = { '%', '@', ',', '?' };

        //Rels segment and extension
        private static readonly string _relationshipPartSegmentName = "_rels";
        private static readonly string _relationshipPartExtensionName = ".rels";

        // Forward Slash
        internal static readonly char ForwardSlashChar = '/';

        // Backward Slash
        internal static readonly char BackwardSlashChar = '\\';

        /// <summary>
        /// pack scheme name
        /// </summary>
        public static readonly string UriSchemePack = "pack";

        #endregion Private Members

        #region Private Class

        /// <summary>
        /// ValidatedPartUri class
        /// Once the partUri has been validated as per the syntax in the OPC spec
        /// we create a ValidatedPartUri, this way we do not have to re-validate 
        /// this. 
        /// This class is heavily used throughout the Packaging APIs and in order
        /// to reduce the parsing and number of allocations for Strings and Uris
        /// we cache the results after parsing.
        /// </summary>
        internal sealed class ValidatedPartUri : Uri, IComparable<ValidatedPartUri>, IEquatable<ValidatedPartUri>
        {
            //------------------------------------------------------
            //
            //  Internal Constructors
            //
            //------------------------------------------------------

            #region Internal Constructors

            internal ValidatedPartUri(string partUriString)
                : this(partUriString, false /*isNormalized*/, true /*computeIsRelationship*/, false /*dummy value as we will compute it later*/)
            {
            }

            //Use this constructor when you already know if a given string is a relationship
            //or no. One place this is used is while creating a normalized uri for a part Uri
            //This will optimize the code and we will not have to parse the Uri to find out
            //if it is a relationship part uri
            internal ValidatedPartUri(string partUriString, bool isRelationshipUri)
                : this(partUriString, false /*isNormalized*/, false /*computeIsRelationship*/, isRelationshipUri)
            {
            }

            #endregion Internal Constructors

            //------------------------------------------------------
            //
            //  Internal Methods
            //
            //------------------------------------------------------

            #region IComparable Methods

            int IComparable<ValidatedPartUri>.CompareTo(ValidatedPartUri otherPartUri)
            {
                return Compare(otherPartUri);
            }

            #endregion IComparable Methods

            #region IEqualityComparer Methods

            bool IEquatable<ValidatedPartUri>.Equals(ValidatedPartUri otherPartUri)
            {
                return Compare(otherPartUri) == 0;
            }

            #endregion IEqualityComparer Methods

            #region Internal Properties

            //------------------------------------------------------
            //
            //  Internal Properties
            //
            //------------------------------------------------------

            //Returns the PartUri string
            internal string PartUriString
            {
                get
                {
                    return _partUriString;
                }
            }

            internal string PartUriExtension
            {
                get
                {
                    if (_partUriExtension == null)
                    {
                        _partUriExtension = Path.GetExtension(_partUriString);

                        //If extension is absent just return the empty string
                        //else remove the leading "." from the returned extension
                        //string
                        if (_partUriExtension.Length > 0)
                            _partUriExtension = _partUriExtension.Substring(1);
                    }
                    return _partUriExtension;
                }
            }

            //Returns the normalized string for the part uri.            
            internal string NormalizedPartUriString
            {
                get
                {
                    if (_normalizedPartUriString == null)
                        _normalizedPartUriString = GetNormalizedPartUriString();

                    return _normalizedPartUriString;
                }
            }

            //Returns the normalized part uri
            internal ValidatedPartUri NormalizedPartUri
            {
                get
                {
                    if (_normalizedPartUri == null)
                        _normalizedPartUri = GetNormalizedPartUri();

                    return _normalizedPartUri;
                }
            }

            //Returns true, if the original string passed to create 
            //this object was normalized
            internal bool IsNormalized
            {
                get
                {
                    return _isNormalized;
                }
            }

            //Returns, true is the partUri is a relationship part uri
            internal bool IsRelationshipPartUri
            {
                get
                {
                    return _isRelationshipPartUri;
                }
            }

            #endregion Internal Properties

            //------------------------------------------------------
            //
            //  Private Methods
            //
            //------------------------------------------------------

            #region Private Constructor

            //Note - isRelationshipPartUri parameter is only meaningful if computeIsRelationship
            //bool is false, in which case, it means that we already know whether the partUriString
            //represents a relationship or no, and as such there is no need to compute/parse to
            //find out if its a relationship.
            private ValidatedPartUri(string partUriString, bool isNormalized, bool computeIsRelationship, bool isRelationshipPartUri)
                : base(partUriString, UriKind.Relative)
            {
                Debug.Assert(partUriString != null && partUriString.Length > 0);

                _partUriString = partUriString;
                _isNormalized = isNormalized;
                if (computeIsRelationship)
                    _isRelationshipPartUri = IsRelationshipUri();
                else
                    _isRelationshipPartUri = isRelationshipPartUri;
            }

            #endregion PrivateConstuctor

            //------------------------------------------------------
            //
            //  Private Methods
            //
            //------------------------------------------------------

            #region Private Methods

            // IsRelationshipPartUri method returns a boolean indicating whether the
            // Uri given is a relationship part Uri or no.
            private bool IsRelationshipUri()
            {
                bool result = false;

                //exit early if the partUri does not end with the relationship extention
                if (!NormalizedPartUriString.EndsWith(_relationshipPartUpperCaseExtension, StringComparison.Ordinal))
                    return false;

                // if uri is /_rels/.rels then we return true
                if (PackUriHelper.ComparePartUri(_containerRelationshipNormalizedPartUri, this) == 0)
                    return true;

                // Look for pattern that matches: "XXX/_rels/YYY.rels" where XXX is zero or more part name characters and
                // YYY is any legal part name characters.
                // We can assume that the string is a valid URI because it would have been rejected by the Uri parsing
                // code in the Uri constructor if it wasn't.
                // Uri's are case insensitive so we can compare them by upper-casing them
                // Essentially, we will just look for the existence of a "folder" called _rels and the trailing extension
                // of .rels.  The folder must also be the last "folder".
                // Comparing using the normalized string to reduce the number of ToUpperInvariant operations
                // required for case-insensitive comparison
                string[] segments = NormalizedPartUriString.Split(_forwardSlashSeparator); //new Uri(_defaultUri, this).Segments; //partUri.Segments cannot be called on a relative Uri;

                // String.Split, will always return an empty string as the
                // first member in the array as the string starts with a "/"

                Debug.Assert(segments.Length > 0 && segments[0] == String.Empty);

                //If the extension was not equal to .rels, we would have exited early.
                Debug.Assert(String.CompareOrdinal((Path.GetExtension(segments[segments.Length - 1])), _relationshipPartUpperCaseExtension) == 0);

                // must be at least two segments and the last one must end with .RELs
                // and the length of the segment should be greater than just the extension.
                if ((segments.Length >= 3) &&
                    (segments[segments.Length - 1].Length > _relationshipPartExtensionName.Length))
                {
                    // look for "_RELS" segment which must be second last segment
                    result = (String.CompareOrdinal(segments[segments.Length - 2], _relationshipPartUpperCaseSegmentName) == 0);
                }

                // In addition we need to make sure that the relationship is not created by taking another relationship
                // as the source of this uri. So XXX/_rels/_rels/YYY.rels.rels would be invalid.
                if (segments.Length > 3 && result == true)
                {
                    if ((segments[segments.Length - 1]).EndsWith(_relsrelsUpperCaseExtension, StringComparison.Ordinal))
                    {
                        // look for "_rels" segment in the third last segment
                        if (String.CompareOrdinal(segments[segments.Length - 3], _relationshipPartUpperCaseSegmentName) == 0)
                            throw new ArgumentException("error");
                    }
                }

                return result;
            }

            //Returns the normalized string for the part uri.            
            //Currently normalizing the PartUriString consists of only one step - 
            //1. Take the wellformed and escaped partUri string and case fold to UpperInvariant            
            private string GetNormalizedPartUriString()
            {
                //Case Fold the partUri string to Invariant Upper case (this helps us perform case insensitive comparison)
                //We follow the Simple case folding specified in the Unicode standard

                if (_isNormalized)
                    return _partUriString;
                else
                    return _partUriString.ToUpperInvariant();
            }

            private ValidatedPartUri GetNormalizedPartUri()
            {
                if (IsNormalized)
                    return this;
                else
                    return new ValidatedPartUri(_normalizedPartUriString,
                                                true /*isNormalized*/,
                                                false /*computeIsRelationship*/,
                                                IsRelationshipPartUri);
            }

            private int Compare(ValidatedPartUri otherPartUri)
            {
                //If otherPartUri is null then we return 1
                if (otherPartUri == null)
                    return 1;

                //Compare the normalized uri strings for the two part uris.
                return String.CompareOrdinal(this.NormalizedPartUriString, otherPartUri.NormalizedPartUriString);
            }

            //------------------------------------------------------
            //
            //  Private Members
            //
            //------------------------------------------------------

            private ValidatedPartUri _normalizedPartUri;
            private string _partUriString;
            private string _normalizedPartUriString;
            private string _partUriExtension;
            private bool _isNormalized;
            private bool _isRelationshipPartUri;

            //String Uppercase variants

            private static readonly string _relationshipPartUpperCaseExtension = ".RELS";
            private static readonly string _relationshipPartUpperCaseSegmentName = "_RELS";
            private static readonly string _relsrelsUpperCaseExtension = String.Concat(_relationshipPartUpperCaseExtension, _relationshipPartUpperCaseExtension);

            //need to use the private constructor to initialize this particular partUri as we need this in the 
            //IsRelationshipPartUri, that is called from the constructor.
            private static readonly Uri _containerRelationshipNormalizedPartUri = new ValidatedPartUri("/_RELS/.RELS",
                                                                                                         true /*isnormalized*/,
                                                                                                         false /*computeIsRelationship*/,
                                                                                                         true /*IsRelationship*/);

            private static readonly char[] _forwardSlashSeparator = { '/' };

            #endregion Private Methods

            //------------------------------------------------------
        }

        #endregion Private Class
    }
}