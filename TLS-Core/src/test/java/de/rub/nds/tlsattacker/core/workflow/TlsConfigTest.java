/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.workflow;

import de.rub.nds.tlsattacker.core.workflow.TlsConfig;
import static org.junit.Assert.assertNotNull;
import org.junit.Test;

/**
 * TODO
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class TlsConfigTest {

    public TlsConfigTest() {
    }

    @Test
    public void testReadFromResource() {
        assertNotNull(TlsConfig.createConfig());
    }
}
