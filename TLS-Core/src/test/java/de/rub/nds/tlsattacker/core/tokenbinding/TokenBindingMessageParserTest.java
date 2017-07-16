/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.tokenbinding;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.TokenBindingKeyParameters;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
public class TokenBindingMessageParserTest {

    private TokenBindingMessageParser parser;

    private ProtocolVersion version;

    private byte[] toParse;

    private TokenBindingKeyParameters parameter;

    @Before
    public void setUp() {
        toParse = ArrayConverter.hexStringToByteArray("");
        version = ProtocolVersion.TLS12;
    }

    /**
     * Test of parseMessageContent method, of class TokenBindingMessageParser.
     */
    @Test
    public void testParseMessageContent() {
        parameter = TokenBindingKeyParameters.ECDSAP256;
        parser = new TokenBindingMessageParser(0, toParse, version, parameter);
        // parser.parse();
    }

}
