import static org.junit.Assert.fail;

import java.io.IOException;
import java.net.MalformedURLException;

import org.apache.logging.log4j.LogManager;
import org.junit.BeforeClass;
import org.junit.Test;

import com.dhedhi.utils.verifywinsign.VerifyWinSign;


public class TestVerifyWinSign {

	public static final String resourcesFolder = "src/test/resources";
	public static final String caStore = "src/test/resources/ca_store";
	
    private static org.apache.logging.log4j.Logger LOGGER = null;
    
    @BeforeClass
    public static void setLogger() throws MalformedURLException
    {
        System.setProperty("log4j.configurationFile","log4j2-test.xml");
        LOGGER = LogManager.getLogger();
    }
	
    // This test is testing a file chrome.exe which is signed by Google
    @Test
    public void TestExeGood() throws IOException {
    	VerifyWinSign verifyWinSign = new VerifyWinSign();
    	verifyWinSign.loadCAStore( caStore );
		boolean result = false;
		try {
			
			result = verifyWinSign.verify( resourcesFolder + "/chrome.exe");
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		org.junit.Assert.assertEquals( result, true );
    }

    @Test
    public void TestAtlasianExe() throws IOException {
        VerifyWinSign verifyWinSign = new VerifyWinSign();
        verifyWinSign.loadCAStore( caStore );

        boolean result = false;
        try {
            
            result = verifyWinSign.verify( resourcesFolder + "/atlassian-confluence-7.12.2-x64.exe");
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        org.junit.Assert.assertEquals( result, true );
    }

    // This test is testing a file openssl.exe which is signed by VMWare with a cert that has now expired
    @Test
    public void TestExeExpired() throws IOException {
    	VerifyWinSign verifyWinSign = new VerifyWinSign();
        verifyWinSign.loadCAStore( caStore );

		boolean result = false;
		try {
			
			result = verifyWinSign.verify( resourcesFolder + "/openssl.exe");
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
        org.junit.Assert.assertEquals( result, false );
    }
    // This should throw an exception since text files do not have signatures
    @Test
    public void TestTextFile() throws IOException {
    	
    	VerifyWinSign verifyWinSign = new VerifyWinSign();
        verifyWinSign.loadCAStore( caStore );

    	try {
			verifyWinSign.verify( resourcesFolder + "/somefile.txt");
    		fail( "Text files do not have signatures." );
    	} catch( Exception e ) {
    		// pass
    		LOGGER.info( e.getMessage() );
    	}
    }
    
    // This should throw an exception since this file does not have signature
    @Test
    public void TestExeFileWithoutSignature() throws IOException {
    	
    	VerifyWinSign verifyWinSign = new VerifyWinSign();
        verifyWinSign.loadCAStore( caStore );

    	try {
			verifyWinSign.verify( resourcesFolder + "/xcopy.exe");
    		fail( "xcopy.exe does not have a digital signature." );
    	} catch( Exception e ) {
    		// pass
    		LOGGER.info( e.getMessage() );
    	}

    }
    
}
