/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.parser;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.SSL2ServerHelloMessage;
import java.util.Arrays;
import java.util.Collection;
import static org.junit.Assert.*;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class SSL2ServerHelloParserTest {

    /*
     * Constructing a SSL2 ServerHelloMessage
     */
    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return Arrays
                .asList(new Object[][] { {
                        ArrayConverter
                                .hexStringToByteArray("820e020001000201ed00060010308201e930820152020106300d06092a864886f70d0101040500305b310b3009060355040613024155311330110603550408130a517565656e736c616e64311a3018060355040a13114372797074536f667420507479204c7464311b301906035504031312546573742043412028313032342062697429301e170d3030313031363232333130335a170d3033303131343232333130335a3063310b3009060355040613024155311330110603550408130a517565656e736c616e64311a3018060355040a13114372797074536f667420507479204c7464312330210603550403131a5365727665722074657374206365727420283531322062697429305c300d06092a864886f70d0101010500034b0030480241009fb3c3842795ff1231520f15ef4611c4ad80e6365b0fdd80d7618de0fc72450934fe556645434c68976afea8a0a5df5f78ffeed764b83f04cb6fff2afefeb9ed0203010001300d06092a864886f70d01010405000381810093d20ac541e65aa986f91187e4db45e2c595781a6c806d731fb46d44a3ba8688c858cd1c06356c446288dfe4f6646195ef4aa67f6571d76b8839f632bfac936769518c93ec485fc9b142f955d27e4ef4f2216b9057e6d7999e41ca80bf1a28a2ca5b504aed84e782c7d2cf369e6a67b988a7f38ad004f8e8c617e3c529bc17f10400800200807aa9b1cbab16a84bd99416f443587d0c"),
                        ProtocolVersion.SSL2,
                        526,
                        HandshakeMessageType.SERVER_HELLO,
                        0 /* 0x00 */,
                        1 /* 0x01 */,
                        ProtocolVersion.SSL2.getValue(),
                        493 /* 0x01ed */,
                        6 /* 0x0006 */,
                        16 /* 0x0010 */,
                        ArrayConverter
                                .hexStringToByteArray("308201e930820152020106300d06092a864886f70d0101040500305b310b3009060355040613024155311330110603550408130a517565656e736c616e64311a3018060355040a13114372797074536f667420507479204c7464311b301906035504031312546573742043412028313032342062697429301e170d3030313031363232333130335a170d3033303131343232333130335a3063310b3009060355040613024155311330110603550408130a517565656e736c616e64311a3018060355040a13114372797074536f667420507479204c7464312330210603550403131a5365727665722074657374206365727420283531322062697429305c300d06092a864886f70d0101010500034b0030480241009fb3c3842795ff1231520f15ef4611c4ad80e6365b0fdd80d7618de0fc72450934fe556645434c68976afea8a0a5df5f78ffeed764b83f04cb6fff2afefeb9ed0203010001300d06092a864886f70d01010405000381810093d20ac541e65aa986f91187e4db45e2c595781a6c806d731fb46d44a3ba8688c858cd1c06356c446288dfe4f6646195ef4aa67f6571d76b8839f632bfac936769518c93ec485fc9b142f955d27e4ef4f2216b9057e6d7999e41ca80bf1a28a2ca5b504aed84e782c7d2cf369e6a67b988a7f38ad004f8e8c617e3c529bc17f1"),
                        ArrayConverter.hexStringToByteArray("040080020080"),
                        ArrayConverter.hexStringToByteArray("7aa9b1cbab16a84bd99416f443587d0c") } });
    }

    private final byte[] message;
    private final ProtocolVersion version;
    private final int messageLength;
    private final HandshakeMessageType type;
    private final int sessionIdHit;
    private final int certificateType;
    private final byte[] protocolVersion;
    private final int certificateLength;
    private final int cipherSuitesLength;
    private final int sessionIdLength;
    private final byte[] certificate;
    private final byte[] cipherSuites;
    private final byte[] sessionId;

    public SSL2ServerHelloParserTest(byte[] message, ProtocolVersion version, int messageLength,
            HandshakeMessageType type, int sessionIdHit, int certificateType, byte[] protocolVersion,
            int certificateLength, int cipherSuitesLength, int sessionIdLength, byte[] certificate,
            byte[] cipherSuites, byte[] sessionId) {
        this.message = message;
        this.version = version;
        this.messageLength = messageLength;
        this.type = type;
        this.sessionIdHit = sessionIdHit;
        this.certificateType = certificateType;
        this.protocolVersion = protocolVersion;
        this.certificateLength = certificateLength;
        this.cipherSuitesLength = cipherSuitesLength;
        this.sessionIdLength = sessionIdLength;
        this.certificate = certificate;
        this.cipherSuites = cipherSuites;
        this.sessionId = sessionId;
    }

    /**
     * Test of parse method, of class SSL2ServerHelloParser.
     */
    @Test
    public void parseTest() {
        SSL2ServerHelloParser parser = new SSL2ServerHelloParser(message, 0, version);
        SSL2ServerHelloMessage msg = parser.parse();
        assertArrayEquals(message, msg.getCompleteResultingMessage().getValue());
        assertTrue(msg.getMessageLength().getValue() == messageLength);
        assertTrue(msg.getType().getValue() == type.getValue());
        assertTrue(msg.getSessionIdHit().getValue() == sessionIdHit);
        assertTrue(msg.getCertificateType().getValue() == certificateType);
        assertArrayEquals(protocolVersion, msg.getProtocolVersion().getValue());
        assertTrue(msg.getCertificateLength().getValue() == certificateLength);
        assertTrue(msg.getCipherSuitesLength().getValue() == cipherSuitesLength);
        assertTrue(msg.getSessionIdLength().getValue() == sessionIdLength);
        assertArrayEquals(certificate, msg.getCertificate().getValue());
        assertArrayEquals(cipherSuites, msg.getCipherSuites().getValue());
        assertArrayEquals(sessionId, msg.getSessionId().getValue());
    }
}
