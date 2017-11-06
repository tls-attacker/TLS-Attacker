/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.record.cipher;

import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeySetGenerator;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.util.tests.IntegrationTests;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;
import org.junit.experimental.categories.Category;

/**
 *

 */
public class KeySetGeneratorTest {

    public KeySetGeneratorTest() {
    }

    @Before
    public void setUp() {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Test that for each implemented CipherSuite/ProtocolVersion a KeySet can
     * be generated without throwing an exception
     */
    @Test
    @Category(IntegrationTests.class)
    public void testGenerateKeySet() {
        for (CipherSuite suite : CipherSuite.getImplemented()) {
            for (ProtocolVersion version : ProtocolVersion.values()) {
                try {
                    if (version == ProtocolVersion.SSL2 || version == ProtocolVersion.SSL3) {
                        continue;
                    }
                    if (version.isTLS13() != suite.isTLS13()) {
                        continue;
                    }
                    TlsContext context = new TlsContext();
                    context.setSelectedCipherSuite(suite);
                    context.setSelectedProtocolVersion(version);
                    assertNotNull(KeySetGenerator.generateKeySet(context));
                } catch (NoSuchAlgorithmException ex) {
                    fail(ex.toString());
                }
            }
        }
    }

}
