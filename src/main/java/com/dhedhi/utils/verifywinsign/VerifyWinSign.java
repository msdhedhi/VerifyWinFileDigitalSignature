package com.dhedhi.utils.verifywinsign;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.operator.OperatorCreationException;

public class VerifyWinSign {

    private static final Logger logger = LogManager.getRootLogger();

    private Map<String,X509Certificate> caCerts = new HashMap<String,X509Certificate>();
    private MessageDigest sha1; // used to compute issuer hashes
    private boolean doAnchorCheck = true; // should we verify the PE file certificates against a CA

    public VerifyWinSign() {
        try {
            sha1 = MessageDigest.getInstance("SHA1"); // we should always find SHA1 provider
        } catch (NoSuchAlgorithmException e) {
        }
    }
    // ------------------------------------------------------------------------------------------------
    // Load the CAs from a folder. We will use these CAs to verify our connections to SSL servers
    // ------------------------------------------------------------------------------------------------
    public synchronized void loadCAStore( String sCAStorePath ) {
        File caFilePath = new File(sCAStorePath);
        
        if( caFilePath.exists() == false ) {
            throw new RuntimeException("Directory: " + sCAStorePath + " does not exist." );
        }
        if( caFilePath.isDirectory() == false ) {
            throw new RuntimeException("Directory: " + sCAStorePath + " does not exist." );
        }
        
        for (File fileEntry : caFilePath.listFiles()) {
            InputStream in = null;
            try {
                in = new FileInputStream(sCAStorePath + "/" + fileEntry.getName());
                CertificateFactory factory = CertificateFactory.getInstance("X.509");
                X509Certificate anchorCert = (X509Certificate) factory.generateCertificate(in);
                
                // add this CA certificate to our caCerts map. Use the issuers subject hash for easy lookup.
                sha1.reset();
                sha1.update(anchorCert.getSubjectX500Principal().getEncoded());
                String sIssuerHash = String.valueOf(WinFile.convertBytesToHex(sha1.digest()));
                caCerts.put(sIssuerHash , anchorCert);
                
                logger.info("Loaded issuer: " + anchorCert.getSubjectX500Principal().getName() + " with hash: " + sIssuerHash);
                
            } catch( Exception e ) {
                throw new RuntimeException("Unable to read file: " + sCAStorePath + "/" + fileEntry.getName() );
            } finally {
                if (in != null) {
                    try {
                        in.close();
                    } catch( IOException e ) {
                        logger.error( "Unable to close file. Readon: " + e.getMessage());
                    }
                }
            }
        }
    }
    
    // ------------------------------------------------------------------------------------------------
    // Verifies a windows PE file by checking its digital signature
    // ------------------------------------------------------------------------------------------------
	public boolean verify(String sFileName ) throws IOException, FileNotFoundException, CMSException, CertificateException, OperatorCreationException {
        
	    logger.info( "Verifying file: " + sFileName );
		WinFile winFile = new WinFile(sFileName);
		winFile.setAnchorCheck( doAnchorCheck );
		
		winFile.loadFileSecurityInfo(  );
		winFile.loadFileHash();
		return winFile.verify(caCerts);
	}
	
    public boolean isDoAnchorCheck() {
        return doAnchorCheck;
    }
    public void setDoAnchorCheck(boolean doAnchorCheck) {
        this.doAnchorCheck = doAnchorCheck;
    }
	
}
