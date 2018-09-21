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
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.util.Random;
import org.apache.commons.lang3.builder.EqualsBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.rules.TemporaryFolder;

public class CertificateDelegateTest {

    private CertificateDelegate delegate;
    private JCommander jcommander;
    private String args[];
    private BadRandom random;

    @Rule
    public final ExpectedException exception = ExpectedException.none();

    @Rule
    public TemporaryFolder folder = new TemporaryFolder();

    @Before
    public void setUp() {
        delegate = new CertificateDelegate();
        jcommander = new JCommander(delegate);
        random = new BadRandom(new Random(0), null);
        Security.addProvider(new BouncyCastleProvider());

    }

    /**
     * Test of getKeystore method, of class CertificateDelegate.
     */
    @Test
    public void testGetKeystore() {
        // Test that the KeyStore gets parsed correctly
        args = new String[2];
        args[0] = "-keystore";
        args[1] = "testkeystore";
        jcommander.parse(args);
        assertTrue("Keystore parameter gets not parsed correctly", delegate.getKeystore().equals(args[1]));
    }

    /**
     * Test of setKeystore method, of class CertificateDelegate.
     */
    @Test
    public void testSetKeystore() {
        delegate.setKeystore("testKey");
        assertTrue("Keystore setter is not working correctly", delegate.getKeystore().equals("testKey"));
    }

    /**
     * Test of getPassword method, of class CertificateDelegate.
     */
    @Test
    public void testGetPassword() {
        // Test that the password gets parsed correctly
        args = new String[2];
        args[0] = "-password";
        args[1] = "testpassword";
        jcommander.parse(args);
        assertTrue("Password parameter gets not parsed correctly", delegate.getPassword().equals(args[1]));
    }

    /**
     * Test of setPassword method, of class CertificateDelegate.
     */
    @Test
    public void testSetPassword() {
        delegate.setPassword("mypassword");
        assertTrue("Password setter is not working correctly", delegate.getPassword().equals("mypassword"));
    }

    /**
     * Test of getAlias method, of class CertificateDelegate.
     */
    @Test
    public void testGetAlias() {
        args = new String[2];
        args[0] = "-alias";
        args[1] = "testalias";
        jcommander.parse(args);
        assertTrue("Alias parameter gets not parsed correctly", delegate.getAlias().equals(args[1]));
    }

    /**
     * Test of setAlias method, of class CertificateDelegate.
     */
    @Test
    public void testSetAlias() {
        delegate.setAlias("myTestAlias");
        assertTrue("Alias setter is not working correctly", delegate.getAlias().equals("myTestAlias"));
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
    public void testApplyDelegate() throws NoSuchAlgorithmException, CertificateException, IOException,
            InvalidKeyException, KeyStoreException, NoSuchProviderException, SignatureException,
            OperatorCreationException {
        KeyStore store = KeyStoreGenerator.createKeyStore(KeyStoreGenerator.createRSAKeyPair(1024, random), random);
        File keyStoreFile = folder.newFile("key.store");
        store.store(new FileOutputStream(keyStoreFile), "password".toCharArray());
        args = new String[6];
        args[0] = "-keystore";
        args[1] = keyStoreFile.getAbsolutePath();
        args[2] = "-password";
        args[3] = "password";
        args[4] = "-alias";
        args[5] = "alias";
        jcommander.parse(args);
        assertTrue("Keystore parameter gets not parsed correctly", delegate.getKeystore().equals(args[1]));
        assertTrue("Password parameter gets not parsed correctly", delegate.getPassword().equals(args[3]));
        assertTrue("Alias parameter gets not parsed correctly", delegate.getAlias().equals(args[5]));
        Config config = Config.createConfig();
        config.setDefaultExplicitCertificateKeyPair(null);
        delegate.applyDelegate(config);
        assertNotNull("Ceritifcate could not be loaded", config.getDefaultExplicitCertificateKeyPair());
    }

    @Test
    public void testApplyDelegateNoKeyStore() {
        args = new String[4];
        args[0] = "-password";
        args[1] = "password";
        args[2] = "-alias";
        args[3] = "default";
        jcommander.parse(args);
        assertTrue("Password parameter gets not parsed correctly", delegate.getPassword().equals(args[1]));
        assertTrue("Alias parameter gets not parsed correctly", delegate.getAlias().equals(args[3]));
        Config config = Config.createConfig();
        config.setDefaultExplicitCertificateKeyPair(null);

        exception.expect(ParameterException.class);
        exception.expectMessage("The following parameters are required for loading a keystore:");
        delegate.applyDelegate(config);
    }

    @Test(expected = ConfigurationException.class)
    public void testApplyDelegateInvalidPassword() {
        args = new String[6];
        args[0] = "-keystore";
        args[1] = "../resources/default.jks";
        args[2] = "-password";
        args[3] = "notthecorrectpassword";
        args[4] = "-alias";
        args[5] = "default";
        jcommander.parse(args);
        Config config = Config.createConfig();
        delegate.applyDelegate(config);
    }

    @Test(expected = ConfigurationException.class)
    public void testApplyDelegateInvalidAlias() {
        args = new String[6];
        args[0] = "-keystore";
        args[1] = "../resources/default.jks";
        args[2] = "-password";
        args[3] = "password";
        args[4] = "-alias";
        args[5] = "notthecorrectalias";
        jcommander.parse(args);
        Config config = Config.createConfig();
        delegate.applyDelegate(config);
    }

    @Test(expected = ConfigurationException.class)
    public void testApplyDelegateInvalidJKS() {
        args = new String[6];
        args[0] = "-keystore";
        args[1] = "../definetlynotacorrect.jks";
        args[2] = "-password";
        args[3] = "password";
        args[4] = "-alias";
        args[5] = "default";
        jcommander.parse(args);
        Config config = Config.createConfig();
        delegate.applyDelegate(config);
    }

    @Test
    public void testNothingSetNothingChanges() {
        Config config = Config.createConfig();
        Config config2 = Config.createConfig();
        delegate.applyDelegate(config);
        assertTrue(EqualsBuilder.reflectionEquals(config, config2));// little
        // ugly
    }
}
