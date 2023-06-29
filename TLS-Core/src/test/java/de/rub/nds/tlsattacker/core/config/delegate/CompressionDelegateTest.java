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
import de.rub.nds.tlsattacker.core.constants.CompressionMethod;
import java.util.LinkedList;
import org.apache.commons.lang3.builder.EqualsBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class CompressionDelegateTest extends AbstractDelegateTest<CompressionDelegate> {

    @BeforeEach
    public void setUp() {
        super.setUp(new CompressionDelegate());
    }

    /** Test of getCompressionMethods method, of class CompressionDelegate. */
    @Test
    public void testGetCompressionMethods() {
        args = new String[2];
        args[0] = "-compression";
        args[1] = "NULL,DEFLATE";
        jcommander.parse(args);
        assertTrue(
                delegate.getCompressionMethods().contains(CompressionMethod.NULL),
                "NULL should get parsed correctly");
        assertTrue(
                delegate.getCompressionMethods().contains(CompressionMethod.DEFLATE),
                "DEFLATE should get parsed correctly");
    }

    @Test
    public void testGetInvalidCompression() {
        args = new String[2];
        args[0] = "-compression";
        args[1] = "DEFNOTACOMPRESSION"; // Not a correct CompressionMethod
        assertThrows(ParameterException.class, () -> jcommander.parse(args));
    }

    /** Test of setCompressionMethods method, of class CompressionDelegate. */
    @Test
    public void testSetCompressionMethods() {
        LinkedList<CompressionMethod> supportedCompressions = new LinkedList<>();
        supportedCompressions.add(CompressionMethod.LZS);
        delegate.setCompressionMethods(supportedCompressions);
        assertEquals(
                supportedCompressions,
                delegate.getCompressionMethods(),
                "CompressionMethods setter is not working correctly");
    }

    /** Test of applyDelegate method, of class CompressionDelegate. */
    @Test
    public void testApplyDelegate() {
        args = new String[2];
        args[0] = "-compression";
        args[1] = "NULL,DEFLATE";
        jcommander.parse(args);
        Config config = Config.createConfig();
        config.setDefaultClientSupportedCompressionMethods();
        config.setDefaultServerSupportedCompressionMethods();
        delegate.applyDelegate(config);
        assertTrue(
                config.getDefaultClientSupportedCompressionMethods()
                        .contains(CompressionMethod.NULL),
                "NULL should get parsed correctly");
        assertTrue(
                config.getDefaultClientSupportedCompressionMethods()
                        .contains(CompressionMethod.DEFLATE),
                "DEFLATE should get parsed correctly");
        assertTrue(
                config.getDefaultServerSupportedCompressionMethods()
                        .contains(CompressionMethod.NULL),
                "NULL should get parsed correctly");
        assertTrue(
                config.getDefaultServerSupportedCompressionMethods()
                        .contains(CompressionMethod.DEFLATE),
                "DEFLATE should get parsed correctly");
    }

    @Test
    public void testNothingSetNothingChanges() {
        Config config = Config.createConfig();
        Config config2 = Config.createConfig();
        delegate.applyDelegate(config);
        assertTrue(EqualsBuilder.reflectionEquals(config, config2, "keyStore", "ourCertificate"));
    }
}
