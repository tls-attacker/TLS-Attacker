package de.rub.nds.tlsattacker.tls.constans;

import static org.junit.Assert.*;

import org.junit.Before;
import org.junit.Test;

import de.rub.nds.tlsattacker.tls.constants.CipherSuite;
import de.rub.nds.tlsattacker.util.ArrayConverter;

import java.util.LinkedList;
import java.util.List;

/**
*
* @author Nurullah Erinola - nurullah.erinola@rub.de
*/
public class CipherSuiteTest {
	
    public CipherSuiteTest() {
    }

    @Before
    public void setUp() {
    }

    /**
     * Test of getCiphersuites method, of class
     * CipherSuite.
     * 
     * size of Array % 2 == 0
     */
    @Test
    public void testPrepare1() {
    	List<CipherSuite> cipherSuites = new LinkedList<>();
    	byte[] values = ArrayConverter.hexStringToByteArray("00010002");
    	cipherSuites = CipherSuite.getCiphersuites(values);
    	// Test
    	assertEquals(2, cipherSuites.size()); 
        assertArrayEquals(ArrayConverter.hexStringToByteArray("0001"), cipherSuites.get(0).getByteValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("0002"), cipherSuites.get(1).getByteValue());
    }
    
    /**
     * Test of getCiphersuites method, of class
     * CipherSuite.
     * 
     * size of Array % 2 != 0
     */
    @Test
    public void testPrepare2() {
    	List<CipherSuite> cipherSuites = new LinkedList<>();
    	byte[] values = ArrayConverter.hexStringToByteArray("0001000200");
    	cipherSuites = CipherSuite.getCiphersuites(values);
    	// Test for Version 1
        assertEquals(2, cipherSuites.size()); 
        assertArrayEquals(ArrayConverter.hexStringToByteArray("0001"), cipherSuites.get(0).getByteValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("0002"), cipherSuites.get(1).getByteValue());        
    }
	
}
