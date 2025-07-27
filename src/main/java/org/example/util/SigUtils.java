package org.example.util;


import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Comparator;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import org.apache.pdfbox.cos.COSArray;
import org.apache.pdfbox.cos.COSBase;
import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.cos.COSObjectKey;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.encryption.SecurityProvider;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.util.Store;

/**
 * Utility class for the signature / timestamp examples.
 *
 * @author Tilman Hausherr
 */
public class SigUtils
{

    private SigUtils()
    {
    }

    /**
     * Get the access permissions granted for this document in the DocMDP transform parameters
     * dictionary. Details are described in the table "Entries in the DocMDP transform parameters
     * dictionary" in the PDF specification.
     *
     * @param doc document.
     * @return the permission value. 0 means no DocMDP transform parameters dictionary exists. Other
     * return values are 1, 2 or 3. 2 is also returned if the DocMDP transform parameters dictionary
     * is found but did not contain a /P entry, or if the value is outside the valid range.
     */
    public static int getMDPPermission(PDDocument doc)
    {
        COSDictionary permsDict = doc.getDocumentCatalog().getCOSObject()
                .getCOSDictionary(COSName.PERMS);
        if (permsDict != null)
        {
            COSDictionary signatureDict = permsDict.getCOSDictionary(COSName.DOCMDP);
            if (signatureDict != null)
            {
                COSArray refArray = signatureDict.getCOSArray(COSName.REFERENCE);
                if (refArray != null)
                {
                    for (int i = 0; i < refArray.size(); ++i)
                    {
                        COSBase base = refArray.getObject(i);
                        if (base instanceof COSDictionary)
                        {
                            COSDictionary sigRefDict = (COSDictionary) base;
                            if (COSName.DOCMDP.equals(sigRefDict.getDictionaryObject(COSName.TRANSFORM_METHOD)))
                            {
                                base = sigRefDict.getDictionaryObject(COSName.TRANSFORM_PARAMS);
                                if (base instanceof COSDictionary)
                                {
                                    COSDictionary transformDict = (COSDictionary) base;
                                    int accessPermissions = transformDict.getInt(COSName.P, 2);
                                    if (accessPermissions < 1 || accessPermissions > 3)
                                    {
                                        accessPermissions = 2;
                                    }
                                    return accessPermissions;
                                }
                            }
                        }
                    }
                }
            }
        }
        return 0;
    }

    /**
     * Set the "modification detection and prevention" permissions granted for this document in the
     * DocMDP transform parameters dictionary. Details are described in the table "Entries in the
     * DocMDP transform parameters dictionary" in the PDF specification.
     *
     * @param doc The document.
     * @param signature The signature object.
     * @param accessPermissions The permission value (1, 2 or 3).
     *
     * @throws IOException if a signature exists.
     */
    public static void setMDPPermission(PDDocument doc, PDSignature signature, int accessPermissions)
            throws IOException
    {
        for (PDSignature sig : doc.getSignatureDictionaries())
        {
            // "Approval signatures shall follow the certification signature if one is present"
            // thus we don't care about timestamp signatures
            if (COSName.DOC_TIME_STAMP.equals(sig.getCOSObject().getItem(COSName.TYPE)))
            {
                continue;
            }
            if (sig.getCOSObject().containsKey(COSName.CONTENTS))
            {
                throw new IOException("DocMDP transform method not allowed if an approval signature exists");
            }
        }

        COSDictionary sigDict = signature.getCOSObject();

        // DocMDP specific stuff
        // all values in the signature dictionary shall be direct objects
        COSDictionary transformParameters = new COSDictionary();
        transformParameters.setItem(COSName.TYPE, COSName.TRANSFORM_PARAMS);
        transformParameters.setInt(COSName.P, accessPermissions);
        transformParameters.setName(COSName.V, "1.2");
        transformParameters.setNeedToBeUpdated(true);
        transformParameters.setDirect(true);

        COSDictionary referenceDict = new COSDictionary();
        referenceDict.setItem(COSName.TYPE, COSName.SIG_REF);
        referenceDict.setItem(COSName.TRANSFORM_METHOD, COSName.DOCMDP);
        referenceDict.setItem(COSName.DIGEST_METHOD, COSName.getPDFName("SHA1"));
        referenceDict.setItem(COSName.TRANSFORM_PARAMS, transformParameters);
        referenceDict.setNeedToBeUpdated(true);
        referenceDict.setDirect(true);

        COSArray referenceArray = new COSArray();
        referenceArray.add(referenceDict);
        sigDict.setItem(COSName.REFERENCE, referenceArray);
        referenceArray.setNeedToBeUpdated(true);
        referenceArray.setDirect(true);

        // Catalog
        COSDictionary catalogDict = doc.getDocumentCatalog().getCOSObject();
        COSDictionary permsDict = new COSDictionary();
        catalogDict.setItem(COSName.PERMS, permsDict);
        permsDict.setItem(COSName.DOCMDP, signature);
        catalogDict.setNeedToBeUpdated(true);
        permsDict.setNeedToBeUpdated(true);
    }

    /**
     * Log if the certificate is not valid for signature usage. Doing this
     * anyway results in Adobe Reader failing to validate the PDF.
     *
     * @param x509Certificate
     * @throws java.security.cert.CertificateParsingException
     */
    public static void checkCertificateUsage(X509Certificate x509Certificate)
            throws CertificateParsingException
    {
        // Check whether signer certificate is "valid for usage"
        // https://stackoverflow.com/a/52765021/535646
        // https://www.adobe.com/devnet-docs/acrobatetk/tools/DigSig/changes.html#id1
        boolean[] keyUsage = x509Certificate.getKeyUsage();
        if (keyUsage != null && !keyUsage[0] && !keyUsage[1])
        {
            // (unclear what "signTransaction" is)
            // https://tools.ietf.org/html/rfc5280#section-4.2.1.3
        }
        List<String> extendedKeyUsage = x509Certificate.getExtendedKeyUsage();
        if (extendedKeyUsage != null &&
                !extendedKeyUsage.contains(KeyPurposeId.id_kp_emailProtection.toString()) &&
                !extendedKeyUsage.contains(KeyPurposeId.id_kp_codeSigning.toString()) &&
                !extendedKeyUsage.contains(KeyPurposeId.anyExtendedKeyUsage.toString()) &&
                !extendedKeyUsage.contains("1.2.840.113583.1.1.5") &&
                // not mentioned in Adobe document, but tolerated in practice
                !extendedKeyUsage.contains("1.3.6.1.4.1.311.10.3.12"))
        {

        }
    }

}

