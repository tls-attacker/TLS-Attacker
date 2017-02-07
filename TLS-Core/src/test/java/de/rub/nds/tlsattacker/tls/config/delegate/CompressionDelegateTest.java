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
import com.beust.jcommander.ParameterException;
import de.rub.nds.tlsattacker.tls.constants.CipherSuite;
import de.rub.nds.tlsattacker.tls.constants.CompressionMethod;
import de.rub.nds.tlsattacker.tls.workflow.TlsConfig;
import java.util.LinkedList;
import org.apache.commons.lang3.builder.EqualsBuilder;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class CompressionDelegateTest {

    private CompressionDelegate delegate;
    private JCommander jcommander;
    private String[] args;

    public CompressionDelegateTest() {
    }

    @Before
    public void setUp() {
        this.delegate = new CompressionDelegate();
        this.jcommander = new JCommander(delegate);
    }

    /**
     * Test of getCompressionMethods method, of class CompressionDelegate.
     */
    @Test
    public void testGetCompressionMethods() {
        args = new String[2];
        args[0] = "-compression";
        args[1] = "NULL,DEFLATE";
        jcommander.parse(args);
        assertTrue("NULL should get parsed correctly", delegate.getCompressionMethods()
                .contains(CompressionMethod.NULL));
        assertTrue("DEFLATE should get parsed correctly",
                delegate.getCompressionMethods().contains(CompressionMethod.DEFLATE));
    }

    @Test(expected = ParameterException.class)
    public void testGetInvalidCompression() {
        args = new String[2];
        args[0] = "-compression";
        args[1] = "DEFNOTACOMPRESSION"; // Not a correct CompressionMethod
        jcommander.parse(args);
    }

    /**
     * Test of setCompressionMethods method, of class CompressionDelegate.
     */
    @Test
    public void testSetCompressionMethods() {
        LinkedList<CompressionMethod> supportedCompressions = new LinkedList<>();
        supportedCompressions.add(CompressionMethod.LZS);
        delegate.setCompressionMethods(supportedCompressions);
        assertTrue("CompressionMethods setter is not working correctly",
                delegate.getCompressionMethods().equals(supportedCompressions));
    }

    /**
     * Test of applyDelegate method, of class CompressionDelegate.
     */
    @Test
    public void testApplyDelegate() {
        args = new String[2];
        args[0] = "-compression";
        args[1] = "NULL,DEFLATE";
        jcommander.parse(args);
        TlsConfig config = new TlsConfig();
        config.setSupportedCompressionMethods(null);
        delegate.applyDelegate(config);
        assertTrue("NULL should get parsed correctly",
                config.getSupportedCompressionMethods().contains(CompressionMethod.NULL));
        assertTrue("DEFLATE should get parsed correctly",
                config.getSupportedCompressionMethods().contains(CompressionMethod.DEFLATE));

    }

    @Test
    public void testNothingSetNothingChanges() {
        TlsConfig config = new TlsConfig();
        TlsConfig config2 = new TlsConfig();
        delegate.applyDelegate(config);
        assertTrue(EqualsBuilder.reflectionEquals(config, config2, "keyStore"));// little
                                                                                // ugly
    }
}
