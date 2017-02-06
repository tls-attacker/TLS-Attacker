/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.config.delegate;

import com.beust.jcommander.JCommander;
import de.rub.nds.tlsattacker.tls.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.tls.workflow.TlsConfig;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class CertificateDelegateTest {

    private CertificateDelegate delegate;
    private JCommander jcommander;
    private String args[];

    public CertificateDelegateTest() {

    }

    @Before
    public void setUp() {
        delegate = new CertificateDelegate();
        jcommander = new JCommander(delegate);

    }

    /**
     * Test of getKeystore method, of class CertificateDelegate.
     */
    @Test
    public void testGetKeystore() {
        // Test that the KeyStore get parsee correctly
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
        // Test that the KeyStore get parsee correctly
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
     */
    @Test
    public void testApplyDelegate() {
        args = new String[6];
        args[0] = "-keystore";
        args[1] = "../resources/default.jks";
        args[2] = "-password";
        args[3] = "password";
        args[4] = "-alias";
        args[5] = "default";
        jcommander.parse(args);
        assertTrue("Keystore parameter gets not parsed correctly", delegate.getKeystore().equals(args[1]));
        assertTrue("Password parameter gets not parsed correctly", delegate.getPassword().equals(args[3]));
        assertTrue("Alias parameter gets not parsed correctly", delegate.getAlias().equals(args[5]));
        TlsConfig config = new TlsConfig();
        config.setKeyStore(null);
        config.setAlias(null);
        config.setPassword(null);
        config.setOurCertificate(null);
        config.setOurX509Certificate(null);
        delegate.applyDelegate(config);
        assertNotNull("Keystore not set correctly in config", config.getKeyStore());
        assertTrue("Password not set correctly in config", config.getPassword().equals(args[3]));
        assertTrue("Alias not set correctly in config", config.getAlias().equals(args[5]));
        assertNotNull("Ceritifcate could not be loaded", config.getOurX509Certificate());
        assertNotNull("Ceritifcate could not be loaded", config.getOurCertificate());
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
        TlsConfig config = new TlsConfig();
        config.setAlias(null);
        config.setPassword(null);
        config.setOurCertificate(null);
        config.setOurX509Certificate(null);
        assertNotNull("Default keystore should be loaded", config.getKeyStore());
        config.setKeyStore(null);
        delegate.applyDelegate(config);
        assertTrue("Password not set correctly in config", config.getPassword().equals(args[1]));
        assertTrue("Alias not set correctly in config", config.getAlias().equals(args[3]));
        assertNull("Keystore should not get loaded if not specified", config.getKeyStore());
        assertNull("Certificate should not get loaded if not specified", config.getOurCertificate());
        assertNull("Certificate should not get laoded if not specified", config.getOurX509Certificate());
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
        TlsConfig config = new TlsConfig();
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
        TlsConfig config = new TlsConfig();
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
        TlsConfig config = new TlsConfig();
        delegate.applyDelegate(config);
    }
}
