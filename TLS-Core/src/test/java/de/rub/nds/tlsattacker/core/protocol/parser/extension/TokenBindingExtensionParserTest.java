/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.TokenBindingKeyParameters;
import de.rub.nds.tlsattacker.core.constants.TokenBindingVersion;
import de.rub.nds.tlsattacker.core.protocol.message.extension.TokenBindingExtensionMessage;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.io.ByteArrayInputStream;
import java.util.Arrays;
import java.util.Collection;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

@RunWith(Parameterized.class)
public class TokenBindingExtensionParserTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return Arrays.asList(new Object[][] { { new byte[] { 0x00, 0x0d, 0x01, 0x02 }, TokenBindingVersion.DRAFT_13, 1,
            new byte[] { TokenBindingKeyParameters.ECDSAP256.getValue() } } });
    }

    private final byte[] extensionBytes;
    private final TokenBindingVersion tokenbindingVersion;
    private final int parameterLength;
    private final byte[] keyParameter;
    private TokenBindingExtensionParser parser;
    private TokenBindingExtensionMessage message;

    public TokenBindingExtensionParserTest(byte[] extensionBytes, TokenBindingVersion tokenbindingVersion,
        int parameterLength, byte[] keyParameter) {
        this.extensionBytes = extensionBytes;
        this.tokenbindingVersion = tokenbindingVersion;
        this.parameterLength = parameterLength;
        this.keyParameter = keyParameter;
    }

    @Before
    public void setUp() {
        parser = new TokenBindingExtensionParser(new ByteArrayInputStream(extensionBytes), Config.createConfig());
    }

    @Test
    public void testParseExtensionMessageContent() {
        message = new TokenBindingExtensionMessage();
        parser.parse(message);
        assertArrayEquals(tokenbindingVersion.getByteValue(), message.getTokenbindingVersion().getValue());
        assertEquals(parameterLength, (long) message.getParameterListLength().getValue());
        assertArrayEquals(keyParameter, message.getTokenbindingKeyParameters().getValue());
    }

}
