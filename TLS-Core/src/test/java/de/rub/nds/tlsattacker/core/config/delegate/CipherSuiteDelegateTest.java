/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.config.delegate;

import static org.junit.jupiter.api.Assertions.*;

import com.beust.jcommander.ParameterException;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import java.util.LinkedList;
import org.apache.commons.lang3.builder.EqualsBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class CipherSuiteDelegateTest extends AbstractDelegateTest<CipherSuiteDelegate> {

    @BeforeEach
    public void setUp() {
        super.setUp(new CipherSuiteDelegate());
    }

    /** Test of getCipherSuites method, of class CiphersuiteDelegate. */
    @Test
    public void testGetCipherSuites() {
        args = new String[2];
        args[0] = "-cipher";
        args[1] = "TLS_RSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_256_CBC_SHA";
        jcommander.parse(args);
        assertTrue(
                delegate.getCipherSuites().contains(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA),
                "TLS_RSA_WITH_AES_128_CBC_SHA should get parsed correctly");
        assertTrue(
                delegate.getCipherSuites().contains(CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA),
                "TLS_RSA_WITH_AES_256_CBC_SHA should get parsed correctly");
    }

    @Test
    public void testGetInvalidCiphersuite() {
        args = new String[2];
        args[0] = "-cipher";
        args[1] = "TLS_RSA_WITH_AES_128_S_256_CBC_SHA"; // Not a correct
        // CipherSuite
        assertThrows(ParameterException.class, () -> jcommander.parse(args));
    }

    /** Test of setCipherSuites method, of class CiphersuiteDelegate. */
    @Test
    public void testSetCipherSuites() {
        LinkedList<CipherSuite> supportedCipherSuites = new LinkedList<>();
        supportedCipherSuites.add(CipherSuite.TLS_FALLBACK_SCSV);
        delegate.setCipherSuites(supportedCipherSuites);
        assertEquals(
                supportedCipherSuites,
                delegate.getCipherSuites(),
                "CipherSuites setter is not working correctly");
    }

    /** Test of applyDelegate method, of class CiphersuiteDelegate. */
    @Test
    public void testApplyDelegate() {
        args = new String[2];
        args[0] = "-cipher";
        args[1] = "TLS_RSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_256_CBC_SHA";
        jcommander.parse(args);
        assertTrue(
                delegate.getCipherSuites().contains(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA),
                "TLS_RSA_WITH_AES_128_CBC_SHA should get parsed correctly");
        assertTrue(
                delegate.getCipherSuites().contains(CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA),
                "TLS_RSA_WITH_AES_256_CBC_SHA should get parsed correctly");
        Config config = Config.createConfig();
        config.setDefaultSelectedCipherSuite(CipherSuite.TLS_AES_128_GCM_SHA256);
        config.setDefaultClientSupportedCipherSuites();
        delegate.applyDelegate(config);
        assertTrue(
                config.getDefaultClientSupportedCipherSuites()
                        .contains(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA),
                "TLS_RSA_WITH_AES_128_CBC_SHA should get parsed correctly");
        assertTrue(
                config.getDefaultClientSupportedCipherSuites()
                        .contains(CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA),
                "TLS_RSA_WITH_AES_256_CBC_SHA should get parsed correctly");
        assertEquals(
                CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA, config.getDefaultSelectedCipherSuite());
    }

    @Test
    public void testNothingSetNothingChanges() {
        Config config = Config.createConfig();
        Config config2 = Config.createConfig();
        delegate.applyDelegate(config);
        assertTrue(EqualsBuilder.reflectionEquals(config, config2, "keyStore", "ourCertificate"));
    }
}
