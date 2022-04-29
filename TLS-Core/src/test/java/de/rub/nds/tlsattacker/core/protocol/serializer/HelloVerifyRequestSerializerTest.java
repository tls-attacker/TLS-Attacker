/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.serializer;

import de.rub.nds.tlsattacker.core.protocol.message.HelloVerifyRequestMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.HelloVerifyRequestParserTest;
import java.util.Collection;
import static org.junit.Assert.assertArrayEquals;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class HelloVerifyRequestSerializerTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return HelloVerifyRequestParserTest.generateData();
    }

    private byte[] message;
    private byte[] protocolVersion;
    private byte cookieLength;
    private byte[] cookie;

    public HelloVerifyRequestSerializerTest(byte[] message, byte[] protocolVersion, byte cookieLength, byte[] cookie) {
        this.message = message;
        this.protocolVersion = protocolVersion;
        this.cookieLength = cookieLength;
        this.cookie = cookie;
    }

    /**
     * Test of serializeHandshakeMessageContent method, of class HelloVerifyRequestSerializer.
     */
    @Test
    public void testSerializeHandshakeMessageContent() {
        HelloVerifyRequestMessage msg = new HelloVerifyRequestMessage();
        msg.setProtocolVersion(protocolVersion);
        msg.setCookieLength(cookieLength);
        msg.setCookie(cookie);
        HelloVerifyRequestSerializer serializer = new HelloVerifyRequestSerializer(msg);
        assertArrayEquals(message, serializer.serializeHandshakeMessageContent());
    }

}
