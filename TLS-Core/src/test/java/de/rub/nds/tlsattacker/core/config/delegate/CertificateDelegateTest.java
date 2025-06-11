/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.config.delegate;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.beust.jcommander.ParameterException;
import de.rub.nds.modifiablevariable.util.BadRandom;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.core.util.KeyStoreGenerator;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.util.Random;
import org.apache.commons.lang3.builder.EqualsBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

public class CertificateDelegateTest extends AbstractDelegateTest<CertificateDelegate> {

    @BeforeEach
    public void setUp() {
        super.setUp(new CertificateDelegate());
    }

    /** Test of getKeystore method, of class CertificateDelegate. */
    @Test
    public void testGetKeystore() {
        // Test that the KeyStore gets parsed correctly
        args = new String[2];
        args[0] = "-keystore";
        args[1] = "testkeystore";
        jcommander.parse(args);
        assertEquals(
                args[1], delegate.getKeystore(), "Keystore parameter gets not parsed correctly");
    }

    /** Test of setKeystore method, of class CertificateDelegate. */
    @Test
    public void testSetKeystore() {
        delegate.setKeystore("testKey");
        assertEquals("testKey", delegate.getKeystore(), "Keystore setter is not working correctly");
    }

    /** Test of getPassword method, of class CertificateDelegate. */
    @Test
    public void testGetPassword() {
        // Test that the password gets parsed correctly
        args = new String[2];
        args[0] = "-password";
        args[1] = "testpassword";
        jcommander.parse(args);
        assertEquals(
                args[1], delegate.getPassword(), "Password parameter gets not parsed correctly");
    }

    /** Test of setPassword method, of class CertificateDelegate. */
    @Test
    public void testSetPassword() {
        delegate.setPassword("mypassword");
        assertEquals(
                "mypassword", delegate.getPassword(), "Password setter is not working correctly");
    }

    /** Test of getAlias method, of class CertificateDelegate. */
    @Test
    public void testGetAlias() {
        args = new String[2];
        args[0] = "-alias";
        args[1] = "testalias";
        jcommander.parse(args);
        assertEquals(args[1], delegate.getAlias(), "Alias parameter gets not parsed correctly");
    }

    /** Test of setAlias method, of class CertificateDelegate. */
    @Test
    public void testSetAlias() {
        delegate.setAlias("myTestAlias");
        assertEquals("myTestAlias", delegate.getAlias(), "Alias setter is not working correctly");
    }

    /**
     * Test of applyDelegate method, of class CertificateDelegate.
     *
     * @throws org.bouncycastle.operator.OperatorCreationException
     * @throws java.security.cert.CertificateException
     * @throws java.security.SignatureException
     * @throws java.io.IOException
     * @throws java.security.NoSuchProviderException
     * @throws java.security.InvalidKeyException
     * @throws java.security.KeyStoreException
     */
    @Test
    public void testApplyDelegate(@TempDir File tempDir)
            throws NoSuchAlgorithmException,
                    CertificateException,
                    IOException,
                    InvalidKeyException,
                    KeyStoreException,
                    NoSuchProviderException,
                    SignatureException,
                    OperatorCreationException {
        BadRandom random = new BadRandom(new Random(0), null);
        KeyStore store =
                KeyStoreGenerator.createKeyStore(
                        KeyStoreGenerator.createRSAKeyPair(1024, random), random);
        File keyStoreFile = new File(tempDir, "key.store");
        try (FileOutputStream fos = new FileOutputStream(keyStoreFile)) {
            store.store(fos, "password".toCharArray());
        }
        args = new String[6];
        args[0] = "-keystore";
        args[1] = keyStoreFile.getAbsolutePath();
        args[2] = "-password";
        args[3] = "password";
        args[4] = "-alias";
        args[5] = "alias";
        jcommander.parse(args);
        assertEquals(
                args[1], delegate.getKeystore(), "Keystore parameter gets not parsed correctly");
        assertEquals(
                args[3], delegate.getPassword(), "Password parameter gets not parsed correctly");
        assertEquals(args[5], delegate.getAlias(), "Alias parameter gets not parsed correctly");
        Config config = new Config();
        config.setDefaultExplicitCertificateChain(null);
        delegate.applyDelegate(config);
        assertNotNull(
                config.getDefaultExplicitCertificateChain(), "Certificate could not be loaded");
    }

    @Test
    public void testApplyDelegateNoKeyStore() {
        args = new String[4];
        args[0] = "-password";
        args[1] = "password";
        args[2] = "-alias";
        args[3] = "default";
        jcommander.parse(args);
        assertEquals(
                args[1], delegate.getPassword(), "Password parameter gets not parsed correctly");
        assertEquals(args[3], delegate.getAlias(), "Alias parameter gets not parsed correctly");
        Config config = new Config();
        config.setDefaultExplicitCertificateChain(null);

        ParameterException exception =
                assertThrows(ParameterException.class, () -> delegate.applyDelegate(config));
        assertTrue(
                exception
                        .getMessage()
                        .startsWith(
                                "The following parameters are required for loading a keystore:"));
    }

    @Test
    public void testApplyDelegateInvalidPassword() {
        args = new String[6];
        args[0] = "-keystore";
        args[1] = "../resources/default.jks";
        args[2] = "-password";
        args[3] = "notthecorrectpassword";
        args[4] = "-alias";
        args[5] = "default";
        jcommander.parse(args);
        Config config = new Config();
        assertThrows(ConfigurationException.class, () -> delegate.applyDelegate(config));
    }

    @Test
    public void testApplyDelegateInvalidAlias() {
        args = new String[6];
        args[0] = "-keystore";
        args[1] = "../resources/default.jks";
        args[2] = "-password";
        args[3] = "password";
        args[4] = "-alias";
        args[5] = "notthecorrectalias";
        jcommander.parse(args);
        Config config = new Config();
        assertThrows(ConfigurationException.class, () -> delegate.applyDelegate(config));
    }

    @Test
    public void testApplyDelegateInvalidJKS() {
        args = new String[6];
        args[0] = "-keystore";
        args[1] = "../definetlynotacorrect.jks";
        args[2] = "-password";
        args[3] = "password";
        args[4] = "-alias";
        args[5] = "default";
        jcommander.parse(args);
        Config config = new Config();
        assertThrows(ConfigurationException.class, () -> delegate.applyDelegate(config));
    }

    @Test
    public void testNothingSetNothingChanges() {
        Config config = new Config();
        Config config2 = new Config();
        delegate.applyDelegate(config);
        assertTrue(EqualsBuilder.reflectionEquals(config, config2, "certificateChainConfig"));
    }
}
