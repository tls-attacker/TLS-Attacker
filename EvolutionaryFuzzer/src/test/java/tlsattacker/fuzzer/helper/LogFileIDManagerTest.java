/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.helper;

import static org.junit.Assert.assertTrue;
import org.junit.Test;

/**
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class LogFileIDManagerTest {

    @Test
    public void testIncrementingIDs() {
        assertTrue("Failure: Incrementing the LogFileIDs failed",
                LogFileIDManager.getInstance().getID() == LogFileIDManager.getInstance().getID() - 1);
    }
}
