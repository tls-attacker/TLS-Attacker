/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.parser;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.HelloVerifyRequestMessage;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.io.ByteArrayInputStream;
import java.util.Arrays;
import java.util.Collection;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertTrue;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class HelloVerifyRequestParserTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return Arrays.asList(
            new Object[][] { { ArrayConverter.hexStringToByteArray("feff1415520276466763250a851c5b9eaeb44676ff3381"),
                ProtocolVersion.DTLS10.getValue(), (byte) 20,
                ArrayConverter.hexStringToByteArray("15520276466763250a851c5b9eaeb44676ff3381") } });
    }

    private final byte[] message;

    private final byte[] protocolVersion;
    private final byte cookieLength;
    private final byte[] cookie;
    private final Config config = Config.createConfig();

    public HelloVerifyRequestParserTest(byte[] message, byte[] protocolVersion, byte cookieLength, byte[] cookie) {
        this.message = message;
        this.protocolVersion = protocolVersion;
        this.cookieLength = cookieLength;
        this.cookie = cookie;
    }

    /**
     * Test of parse method, of class HelloVerifyRequestParser.
     */
    @Test
    public void testParse() {
        HelloVerifyRequestParser parser = new HelloVerifyRequestParser(new ByteArrayInputStream(message),
            ProtocolVersion.DTLS10, new TlsContext(config));
        HelloVerifyRequestMessage msg = new HelloVerifyRequestMessage();
        parser.parse(msg);
        assertArrayEquals(protocolVersion, msg.getProtocolVersion().getValue());
        assertArrayEquals(cookie, msg.getCookie().getValue());
        assertTrue(cookieLength == msg.getCookieLength().getValue());
    }
}
