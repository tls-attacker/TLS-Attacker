/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.tokenbinding;

import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import org.junit.Before;
import org.junit.Test;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
public class TokenBindingMessageSerializerTest {

    private TokenBindingMessageSerializer serializer;

    private ProtocolVersion version;

    private TokenBindingMessage message;

    @Before
    public void setUp() {
        message = new TokenBindingMessage();
        version = ProtocolVersion.TLS12;
        serializer = new TokenBindingMessageSerializer(message, version);
    }

    /**
     * Test of serializeProtocolMessageContent method, of class
     * TokenBindingMessageSerializer.
     */
    @Test
    public void testSerializeProtocolMessageContent() {
        // serializer.serialize();
    }

}
