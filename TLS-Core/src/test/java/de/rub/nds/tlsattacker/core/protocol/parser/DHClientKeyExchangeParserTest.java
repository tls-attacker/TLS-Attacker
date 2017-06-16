/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.parser;

import de.rub.nds.tlsattacker.core.protocol.parser.DHClientKeyExchangeParser;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.DHClientKeyExchangeMessage;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import java.util.Arrays;
import java.util.Collection;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
@RunWith(Parameterized.class)
public class DHClientKeyExchangeParserTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return Arrays
                .asList(new Object[][] { {
                        ArrayConverter
                                .hexStringToByteArray("100001020100c2bf1e41e5f67a882cd9b0150edbeb95d982fb97a0a0732739d96ac5af92bfeaeb7040419a7be326fd1a43f02fd264cd58d95d0a4f9b81636bae126b50863c49cb386e23a8f2a51c8b272fa2f5321cfce4dbff6fc6e769246f887007434d2e6315edaf2fcc8d66f9f42c67ff08cd4fde092dece15656035a9dd1aedb0091dbae42b1501306c21cedb5c63858456b1f01484c3df3f0a6871070212d9448849e1057f4257917aa3bcb9287b2b4e4eaa6c8c4f49d3c737259c22b68dc6eb6288a09ddf70a5bf4348ebd96e411ef496a3d478b0e3fd07ff29be6d1b246e0086793b9036df0a39cae63e1647fef812c36766dda2de62154c11b5eb216e8bd813cb71d"),
                        0,
                        ArrayConverter
                                .hexStringToByteArray("100001020100c2bf1e41e5f67a882cd9b0150edbeb95d982fb97a0a0732739d96ac5af92bfeaeb7040419a7be326fd1a43f02fd264cd58d95d0a4f9b81636bae126b50863c49cb386e23a8f2a51c8b272fa2f5321cfce4dbff6fc6e769246f887007434d2e6315edaf2fcc8d66f9f42c67ff08cd4fde092dece15656035a9dd1aedb0091dbae42b1501306c21cedb5c63858456b1f01484c3df3f0a6871070212d9448849e1057f4257917aa3bcb9287b2b4e4eaa6c8c4f49d3c737259c22b68dc6eb6288a09ddf70a5bf4348ebd96e411ef496a3d478b0e3fd07ff29be6d1b246e0086793b9036df0a39cae63e1647fef812c36766dda2de62154c11b5eb216e8bd813cb71d"),
                        HandshakeMessageType.CLIENT_KEY_EXCHANGE,
                        258,
                        256,
                        ArrayConverter
                                .hexStringToByteArray("c2bf1e41e5f67a882cd9b0150edbeb95d982fb97a0a0732739d96ac5af92bfeaeb7040419a7be326fd1a43f02fd264cd58d95d0a4f9b81636bae126b50863c49cb386e23a8f2a51c8b272fa2f5321cfce4dbff6fc6e769246f887007434d2e6315edaf2fcc8d66f9f42c67ff08cd4fde092dece15656035a9dd1aedb0091dbae42b1501306c21cedb5c63858456b1f01484c3df3f0a6871070212d9448849e1057f4257917aa3bcb9287b2b4e4eaa6c8c4f49d3c737259c22b68dc6eb6288a09ddf70a5bf4348ebd96e411ef496a3d478b0e3fd07ff29be6d1b246e0086793b9036df0a39cae63e1647fef812c36766dda2de62154c11b5eb216e8bd813cb71d") }, });
    }

    private byte[] message;
    private int start;
    private byte[] expectedPart;

    private HandshakeMessageType type;
    private int length;

    private int serializedKeyLength;
    private byte[] serializedKey;

    public DHClientKeyExchangeParserTest(byte[] message, int start, byte[] expectedPart, HandshakeMessageType type,
            int length, int serializedKeyLength, byte[] serializedKey) {
        this.message = message;
        this.start = start;
        this.expectedPart = expectedPart;
        this.type = type;
        this.length = length;
        this.serializedKeyLength = serializedKeyLength;
        this.serializedKey = serializedKey;
    }

    /**
     * Test of parse method, of class DHClientKeyExchangeParser.
     */
    @Test
    public void testParse() {
        DHClientKeyExchangeParser parser = new DHClientKeyExchangeParser(start, message, ProtocolVersion.TLS12);
        DHClientKeyExchangeMessage msg = parser.parse();
        assertArrayEquals(expectedPart, msg.getCompleteResultingMessage().getValue());
        assertTrue(msg.getLength().getValue() == length);
        assertTrue(msg.getType().getValue() == type.getValue());
        assertTrue(serializedKeyLength == msg.getPublicKeyLength().getValue());
        assertArrayEquals(serializedKey, msg.getPublicKey().getValue());
    }

}
