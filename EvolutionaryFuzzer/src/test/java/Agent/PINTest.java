/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package Agent;

import java.io.File;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class PINTest {

    @BeforeClass
    public static void setUpClass() {
    }

    @AfterClass
    public static void tearDownClass() {
    }

    public PINTest() {
    }

    @Test
    public void testPinExists() {
	File f = new File("PIN/pin.sh");
	assertTrue("Failure: Could not find PIN implementation", f.exists());
	f = new File("PinScripts/MyPinTool.cpp");
	assertTrue("Failure: Could not find PIN script", f.exists());

    }
}
