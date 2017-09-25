package com.dhedhi.utils.verifywinsign;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Iterator;
import java.util.Map;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.pkcs.ContentInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.Store;

import com.dhedhi.utils.verifywinsign.exceptions.WindowsPEFileFormatException;

/*
 * The following class represents a windows PE file as defined in the links below
 * http://download.microsoft.com/download/9/c/5/9c5b2167-8017-4bae-9fde-d599bac8184a/Authenticode_PE.docx
 * https://msdn.microsoft.com/en-us/library/windows/desktop/ms680547(v=vs.85).aspx
 */

public class WinFile {

    static {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }

    private static final Logger logger = LogManager.getRootLogger();

    public static final int iBlockSize = 4096; // how many bytes are we going to
                                               // read at a time from the input
                                               // file

    private byte[] computedFileHash = null; // file hash computed

    private byte[] storedFileHash = null; // file hash as stored in the windows
                                          // binary

    private String sFileName; // the name/path of the file we are working with

    private CMSSignedData signature;
    private String digestAlgorithm;

    private int iPEOffset;
    private long dirSecurityOffset;
    //private long coffSymbolTableOffset;

    private boolean fileIs64Bit = false;

    private boolean dateValidityCheck = true; // check if cert has expired
    private boolean anchorCheck = true; // check cert against an anchor ( i.e.
                                        // CA ) cert

    private MessageDigest sha1;

    public WinFile(String sFileName) {

        this.sFileName = sFileName;
        try {
            sha1 = MessageDigest.getInstance("SHA1");
        } catch (NoSuchAlgorithmException e) {
        }
        ;
    }

    public void loadFileSecurityInfo() throws IOException, FileNotFoundException {

        byte[] fileBlock = new byte[iBlockSize];
        byte[] fileSecurityInfo = null;

        File file = new File(sFileName);

        if (file.exists() == false) {
            throw new FileNotFoundException();
        }

        InputStream input = null;

        try {
            input = new BufferedInputStream(new FileInputStream(file));
            int iBytesRead = input.read(fileBlock, 0, iBlockSize);
            if (iBytesRead != iBlockSize) {
                throw new WindowsPEFileFormatException("Unable to read file block of size 4096");
            }

            if (fileBlock[0] == 0x4D && fileBlock[1] == 0x53 && fileBlock[2] == 0x43 && fileBlock[3] == 0x46) {
                throw new WindowsPEFileFormatException("Cab files are not supported");
            }

            // check if valid DOS file. Must start with characters MZ
            if (fileBlock[0] != 0x4D || fileBlock[1] != 0x5A) {
                throw new WindowsPEFileFormatException("Invalid magic number.");
            }

            iPEOffset = ConvertToUint16(fileBlock[61], fileBlock[60]);
            // System.out.println( "iPEOffset : " +
            // Integer.toHexString(iPEOffset) + " " + fileBlock[60] + " " +
            // fileBlock[61]);

            if ((iPEOffset + 160) >= iBlockSize) {
                throw new WindowsPEFileFormatException("PE Offset is out of range");
            }

            // check if valid windows NT file format
            // check for PE offset 0x50 = 'P' 0x45 = 'E'
            if (fileBlock[iPEOffset] != 0x50 || fileBlock[iPEOffset + 1] != 0x45) {
                throw new WindowsPEFileFormatException("PE Offset is invalid.");
            }

            // find binary type
            int binaryType = ConvertToUint16(fileBlock[iPEOffset + 4 + 20 + 1], fileBlock[iPEOffset + 20 + 4]);
            // System.out.println( "Binary Type: " +
            // Integer.toHexString(binaryType) );
            // For 64 bit exe, we need to skip some more to get the security
            // offset.
            int extraBytes = 0;
            if (binaryType == 0x20b) {
                // extraBytes = 16;
                fileIs64Bit = true;
                extraBytes = 16;
                // throw new WindowsPEFileFormatException("64 bit binaries are
                // currently not supported.");
            }

            // System.out.println( "iPEOffset : " +
            // Integer.toHexString(iPEOffset) );

            dirSecurityOffset = ConvertToUint32(fileBlock[iPEOffset + extraBytes + 152 + 3],
                    fileBlock[iPEOffset + extraBytes + 152 + 2], fileBlock[iPEOffset + extraBytes + 152 + 1],
                    fileBlock[iPEOffset + extraBytes + 152]);
            long dirSecuritySize = ConvertToUint32(fileBlock[iPEOffset + extraBytes + 156 + 3],
                    fileBlock[iPEOffset + extraBytes + 156 + 2], fileBlock[iPEOffset + extraBytes + 156 + 1],
                    fileBlock[iPEOffset + extraBytes + 156]);
            //coffSymbolTableOffset = ConvertToUint32(fileBlock[iPEOffset + 12 + 3], fileBlock[iPEOffset + 12 + 2],
            //        fileBlock[iPEOffset + 12 + 1], fileBlock[iPEOffset + 12]);

            // System.out.println( "dirSecurityOffset: " +
            // Long.toHexString(dirSecurityOffset) + " coffSymbolTableOffset: "
            // + coffSymbolTableOffset );

            if (dirSecuritySize <= 8) {
                throw new WindowsPEFileFormatException("dirSecuritySize is invalid.");
            }

            // Now skip to the part where we have the file security info in the file i.e. the certificate etc
            long bytesToRead = ( dirSecurityOffset + 8 ) - iBytesRead;
            long blocks = (bytesToRead >> 12);  // or in other words ( bytesToRead / 4096 )
            int remainder = (int) (bytesToRead - (blocks << 12));  // bytes that remain after we have read "blocks" of 4096 bytes
            
            while (blocks-- > 0) {
                iBytesRead = input.read(fileBlock, 0, iBlockSize);
            }

            if (remainder > 0) {
                iBytesRead = input.read(fileBlock, 0, remainder);
            }
            
            fileSecurityInfo = new byte[(int) (dirSecuritySize - 8)];

            // file pointer is now pointing to the place where we should now
            // start reading the signer information
            // This should be a PKCS7 structure
            iBytesRead = input.read(fileSecurityInfo, 0, (int)(dirSecuritySize - 8));
            
            if( iBytesRead != dirSecuritySize - 8 ) {
                throw new WindowsPEFileFormatException("Unable to read file security info.");
            }

        } finally {
            if (input != null) {
                input.close();
            }
        }

        // We now have the security info.
        // Attempt to load it in the ASN1Object structure
        // If this fails then we do not have a valid signature
        ASN1InputStream ais = null;
        ASN1Object asn1 = null;

        try {

            ais = new ASN1InputStream(fileSecurityInfo);
            asn1 = ais.readObject();

            ContentInfo ci = ContentInfo.getInstance(asn1);

            ASN1ObjectIdentifier typeId = ci.getContentType();
            if (!typeId.equals(PKCSObjectIdentifiers.signedData)) {
                throw new WindowsPEFileFormatException("Not a pkcs7 signature.");
            }

            try {
                signature = new CMSSignedData(ci.getEncoded());
            } catch (CMSException e) {
                throw new WindowsPEFileFormatException("Unable to load signature.");
            }

            // We will only attempt to validate the first signature
            if (signature.getDigestAlgorithmIDs().size() == 0) {
                throw new WindowsPEFileFormatException("Unable to find any signature.");
            }
            if (signature.getDigestAlgorithmIDs().size() > 1) {
                throw new WindowsPEFileFormatException("Found more than one signature.");
            }

            digestAlgorithm = signature.getDigestAlgorithmIDs().iterator().next().getAlgorithm().toString();

            DERSequence seq = (DERSequence) signature.getSignedContent().getContent();
            DERSequence seq1 = (DERSequence) seq.getObjectAt(1);
            DEROctetString seq2 = (DEROctetString) seq1.getObjectAt(1);

            storedFileHash = seq2.getOctets(); // this is the file hash as
                                               // stored in the signer info of
                                               // the EXE file
            logger.info("File hash stored in PKCS7 cert: " + String.valueOf(convertBytesToHex(storedFileHash)));

        } finally {
            if (ais != null) {
                try {
                    ais.close();
                } catch (Exception e) {

                }
            }
        }
    }

    public void loadFileHash() throws IOException, CMSException {

        byte[] fileBlock = new byte[iBlockSize];
        MessageDigest md = null;
        try {
            // hash algorithm comes from the PKCS7 certificate read earlier
            md = MessageDigest.getInstance(digestAlgorithm, "BC");
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new WindowsPEFileFormatException("Algorithm or provider not found. " + e.getMessage());
        }

        File file = new File(sFileName);

        if (file.exists() == false) {
            throw new FileNotFoundException();
        }

        InputStream input = null;

        int extraBytes = 0;
        if (fileIs64Bit) {
            extraBytes = 16;
        }

        try {
            input = new BufferedInputStream(new FileInputStream(file));
            int iBytesRead = input.read(fileBlock, 0, iBlockSize);

            int pe = iPEOffset + 88;

            md.update(fileBlock, 0, pe); // 0 to 88

            // then skip 4 for checksum
            pe += 4;

            md.update(fileBlock, pe, 60 + extraBytes); // 92 to 152 + extraBytes

            pe += (68 + extraBytes);

            md.update(fileBlock, pe, iBytesRead - pe); // 92 to 152 + extraBytes

            // We now need to read until the dirSecurityOffset and hash bytes until that point
            long bytesToRead = dirSecurityOffset - iBytesRead;
            long blocks = (bytesToRead >> 12);  // or in other words bytesToRead / 4096
            int remainder = (int) (bytesToRead - (blocks << 12));

            while (blocks-- > 0) {
                iBytesRead = input.read(fileBlock, 0, iBlockSize);
                md.update(fileBlock, 0, iBytesRead);
            }
            
            if( remainder > 0 ) {
                iBytesRead = input.read(fileBlock, 0, remainder);
                md.update(fileBlock, 0, remainder );
            }

            computedFileHash = md.digest(); // compute the hash of the file using the "digestAlgorithm" found earlier

            logger.info("Computed FileHash: " + String.valueOf(convertBytesToHex(computedFileHash)));

        } finally {
            input.close();
        }
    }

    public boolean verify(Map<String,X509Certificate> caStoreHashMap)
            throws IOException, CMSException, CertificateException, OperatorCreationException {

        // first make sure the file hash matches the stored file hash
        if (storedFileHash == null || computedFileHash == null) {
            return false;
        }
        if (storedFileHash.length != computedFileHash.length) {
            logger.error("File hashes length do not match.");
            return false;
        }

        for (int i = 0; i < storedFileHash.length; i++) {
            if (storedFileHash[i] != computedFileHash[i]) {
                logger.error("File hashes do not match.");
                return false;
            }
        }

        logger.info("File hashes match. File has not been modified.");

        // Now verify the validity of the signing certificate
        Store<X509CertificateHolder> certStore = signature.getCertificates(); // This
                                                                              // is
                                                                              // where
                                                                              // you
                                                                              // access
                                                                              // embedded
                                                                              // certificates
        SignerInformationStore signers = signature.getSignerInfos();
        Collection<SignerInformation> c = signers.getSigners();
        Iterator<SignerInformation> it = c.iterator();

        boolean isValid = false;
        while (it.hasNext()) {
            SignerInformation signer = (SignerInformation) it.next();
            Collection<X509CertificateHolder> certCollection = certStore.getMatches(signer.getSID());

            Iterator<X509CertificateHolder> certIt = certCollection.iterator();
            X509CertificateHolder cert = (X509CertificateHolder) certIt.next();

            if (signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(cert)) == false) {
                logger.error("Certificate " + cert.getSubject().toString() + " is not valid.");
                isValid = false;
                return false;
            } else {
                logger.info("Certificate " + cert.getSubject().toString() + " is valid with issuer: "
                        + cert.getIssuer().toString());
            }

            if (dateValidityCheck == true) {
                // Check for Expiry
                boolean notExpired = cert.isValidOn(new java.util.Date());
                if (notExpired == false) {
                    logger.error("Certificate " + cert.getSubject().toString() + " is no longer valid.");
                    isValid = false;
                    return false;
                }
            }

            if (anchorCheck == true) {
                // Check for trust anchor
                // First get the issuer's hash. We will then attempt to lookup
                // the issuer in our CA stor
                sha1.reset();
                sha1.update(cert.getIssuer().getEncoded());
                String sIssuerHash = String.valueOf(convertBytesToHex(sha1.digest()));
                if( caStoreHashMap.containsKey( sIssuerHash ) == false ) {
                    throw new WindowsPEFileFormatException( "Certificate with isuser hash: " + sIssuerHash + " and subject: " + cert.getIssuer().toString() + " was not found in CA store.");
                }
                
                X509Certificate trustAnchor = caStoreHashMap.get(sIssuerHash);

                // Now verify against the anchor cert
                X509Certificate peCert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(cert);
                try {
                    peCert.verify(trustAnchor.getPublicKey()); // verify it was
                                                              // signed using
                                                              // anchor cert's
                                                              // public key
                    
                    logger.info( "PE file certificate verified using CA: " + trustAnchor.getSubjectDN().getName());
                    
                } catch (Exception e) {
                    logger.error("Signing certificate is not trusted");
                    isValid = false;
                    return false;
                }
            }

            // if all checks passed then assume cert is valid.
            isValid = true;
        }

        if (isValid == false) {
            logger.error("Unable to validate the PKCS7 certificate.");
            return false;
        }

        logger.info("PKCS7 certificate is valid");

        return true;
    }

    private long ConvertToUint32(byte iHandle1, byte iHandle2, byte iHandle3, byte iHandle4) {
        byte array[] = new byte[] { iHandle1, iHandle2, iHandle3, iHandle4 };

        ByteBuffer wrapped = ByteBuffer.wrap(array);
        return wrapped.getInt();
    }

    private int ConvertToUint16(byte iHandle1, byte iHandle2) {
        int iHandle = 0;
        iHandle = iHandle1;
        iHandle = (iHandle & 0xFF) << 8;
        iHandle = iHandle | (iHandle2 & 0xFF);
        return iHandle; // return the combined handle
    }

    private static char hex[] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };

    public static char[] convertBytesToHex(byte[] bytes) {
        char buf[] = new char[bytes.length * 2];
        int index = 0;
        for (byte b : bytes) {
            buf[index++] = hex[(b >> 4) & 0xf];
            buf[index++] = hex[b & 0xf];
        }
        return buf;
    }

    public boolean isDateValidityCheck() {
        return dateValidityCheck;
    }

    public void setDateValidityCheck(boolean dateValidityCheck) {
        this.dateValidityCheck = dateValidityCheck;
    }

    public boolean isAnchorCheck() {
        return anchorCheck;
    }

    public void setAnchorCheck(boolean anchorCheck) {
        this.anchorCheck = anchorCheck;
    }
}
