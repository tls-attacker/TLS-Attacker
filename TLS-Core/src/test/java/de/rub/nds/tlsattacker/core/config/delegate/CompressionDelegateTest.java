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
import de.rub.nds.tlsattacker.core.constants.CompressionMethod;
import java.util.LinkedList;
import org.apache.commons.lang3.builder.EqualsBuilder;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

public class CompressionDelegateTest {

    private CompressionDelegate delegate;
    private JCommander jcommander;
    private String[] args;

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
        Config config = Config.createConfig();
        config.setDefaultClientSupportedCompressionMethods(new CompressionMethod[0]);
        config.setDefaultServerSupportedCompressionMethods(new CompressionMethod[0]);
        delegate.applyDelegate(config);
        assertTrue("NULL should get parsed correctly",
                config.getDefaultClientSupportedCompressionMethods().contains(CompressionMethod.NULL));
        assertTrue("DEFLATE should get parsed correctly", config.getDefaultClientSupportedCompressionMethods()
                .contains(CompressionMethod.DEFLATE));
        assertTrue("NULL should get parsed correctly",
                config.getDefaultServerSupportedCompressionMethods().contains(CompressionMethod.NULL));
        assertTrue("DEFLATE should get parsed correctly", config.getDefaultServerSupportedCompressionMethods()
                .contains(CompressionMethod.DEFLATE));

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
