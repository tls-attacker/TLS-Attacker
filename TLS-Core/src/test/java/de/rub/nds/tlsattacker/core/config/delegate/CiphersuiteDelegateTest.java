/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.config.delegate;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.ParameterException;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import java.util.LinkedList;
import org.apache.commons.lang3.builder.EqualsBuilder;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.Test;

public class CiphersuiteDelegateTest {

    private CiphersuiteDelegate delegate;
    private JCommander jcommander;
    private String args[];

    @Before
    public void setUp() {
        delegate = new CiphersuiteDelegate();
        jcommander = new JCommander(delegate);
    }

    /**
     * Test of getCipherSuites method, of class CiphersuiteDelegate.
     */
    @Test
    public void testGetCipherSuites() {
        args = new String[2];
        args[0] = "-cipher";
        args[1] = "TLS_RSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_256_CBC_SHA";
        jcommander.parse(args);
        assertTrue("TLS_RSA_WITH_AES_128_CBC_SHA should get parsed correctly",
                delegate.getCipherSuites().contains(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA));
        assertTrue("TLS_RSA_WITH_AES_256_CBC_SHA should get parsed correctly",
                delegate.getCipherSuites().contains(CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA));
    }

    @Test(expected = ParameterException.class)
    public void testGetInvalidCiphersuite() {
        args = new String[2];
        args[0] = "-cipher";
        args[1] = "TLS_RSA_WITH_AES_128_S_256_CBC_SHA"; // Not a correct
                                                        // CipherSuite
        jcommander.parse(args);
    }

    /**
     * Test of setCipherSuites method, of class CiphersuiteDelegate.
     */
    @Test
    public void testSetCipherSuites() {
        LinkedList<CipherSuite> supportedCipherSuites = new LinkedList<>();
        supportedCipherSuites.add(CipherSuite.TLS_FALLBACK_SCSV);
        delegate.setCipherSuites(supportedCipherSuites);
        assertTrue("CipherSuites setter is not working correctly",
                delegate.getCipherSuites().equals(supportedCipherSuites));
    }

    /**
     * Test of applyDelegate method, of class CiphersuiteDelegate.
     */
    @Test
    public void testApplyDelegate() {
        args = new String[2];
        args[0] = "-cipher";
        args[1] = "TLS_RSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_256_CBC_SHA";
        jcommander.parse(args);
        assertTrue("TLS_RSA_WITH_AES_128_CBC_SHA should get parsed correctly",
                delegate.getCipherSuites().contains(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA));
        assertTrue("TLS_RSA_WITH_AES_256_CBC_SHA should get parsed correctly",
                delegate.getCipherSuites().contains(CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA));
        Config config = Config.createConfig();
        config.setDefaultSelectedCipherSuite(CipherSuite.TLS_AES_128_GCM_SHA256);
        config.setDefaultClientSupportedCiphersuites(new CipherSuite[0]);
        delegate.applyDelegate(config);
        assertTrue("TLS_RSA_WITH_AES_128_CBC_SHA should get parsed correctly", config
                .getDefaultClientSupportedCiphersuites().contains(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA));
        assertTrue("TLS_RSA_WITH_AES_256_CBC_SHA should get parsed correctly", config
                .getDefaultClientSupportedCiphersuites().contains(CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA));
        assertEquals(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA, config.getDefaultSelectedCipherSuite());

    }

    @Test
    public void testNothingSetNothingChanges() {
        Config config = Config.createConfig();
        Config config2 = Config.createConfig();
        delegate.applyDelegate(config);
        assertTrue(EqualsBuilder.reflectionEquals(config, config2, "keyStore", "ourCertificate"));// little
        // ugly
    }
}
