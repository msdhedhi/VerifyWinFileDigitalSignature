package com.dhedhi.utils.verifywinsign;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.Security;
import java.security.cert.CertificateException;

import org.bouncycastle.cms.CMSException;
import org.bouncycastle.operator.OperatorCreationException;

public class VerifyWinSign {

	public boolean verify(String sFileName, String caStore) throws IOException, FileNotFoundException, CMSException, CertificateException, OperatorCreationException {

        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        
		WinFile winFile = new WinFile(sFileName);
		//winFile.setAnchorCheck( false );
		
		winFile.loadFileSecurityInfo(  );
		winFile.loadFileHash();
		return winFile.verify(caStore);
	}
	
}
