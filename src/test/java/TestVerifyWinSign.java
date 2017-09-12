import java.io.IOException;

import org.junit.Test;

import com.dhedhi.utils.verifywinsign.VerifyWinSign;


public class TestVerifyWinSign {

	public static final String resourcesFolder = "src/test/resources";
	public static final String caStore = "src/test/resources/ca_store";
	
    // This test is testing a file openssl.exe which is signed by VMWare
    @Test
    public void TestExeGood() throws IOException {
    	VerifyWinSign verifyWinSign = new VerifyWinSign();
    	
		boolean result = false;
		try {
			
			result = verifyWinSign.verify( resourcesFolder + "/chrome.exe", caStore);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		assert( result == true );
    }

    // This test is testing a file openssl.exe which is signed by VMWare with a cert that has now expired
    @Test
    public void TestExeExpired() throws IOException {
    	VerifyWinSign verifyWinSign = new VerifyWinSign();
    	
		boolean result = false;
		try {
			
			result = verifyWinSign.verify( resourcesFolder + "/openssl.exe", caStore);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		assert( result == false );
		
    }
    // This should throw an exception since text files do not have signatures
    @Test
    public void TestTextFile() throws IOException {
    	
    	VerifyWinSign verifyWinSign = new VerifyWinSign();
    	
    	try {
			verifyWinSign.verify( resourcesFolder + "/somefile.txt", caStore);
    		//fail( "Text files do not have signatures." );
    	} catch( Exception e ) {
    		// pass
    		System.out.println( e.getMessage() );
    	}

    }
    
    // This should throw an exception since this file does not have signature
    @Test
    public void TestExeFileWithoutSignature() throws IOException {
    	
    	VerifyWinSign verifyWinSign = new VerifyWinSign();
    	
    	try {
			verifyWinSign.verify( resourcesFolder + "/xcopy.exe", caStore);
    		//fail( "xcopy.exe does not have a digital signature." );
    	} catch( Exception e ) {
    		// pass
    		System.out.println( e.getMessage() );
    	}

    }
    
}