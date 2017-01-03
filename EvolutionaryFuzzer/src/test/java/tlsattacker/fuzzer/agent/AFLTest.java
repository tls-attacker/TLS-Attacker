/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.agent;

import de.rub.nds.tlsattacker.tests.IntegrationTest;
import java.io.File;
import static org.junit.Assert.assertTrue;
import org.junit.experimental.categories.Category;

/**
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class AFLTest {

    @Category(IntegrationTest.class)
    public void testAflexists() {
        File f = new File("AFL/afl-as");
        assertTrue("Failure: Tool afl-as was not found", f.exists());
        f = new File("AFL/afl-showmap");
        assertTrue("Failure: Tool afl-showmap was not found", f.exists());

    }

}
