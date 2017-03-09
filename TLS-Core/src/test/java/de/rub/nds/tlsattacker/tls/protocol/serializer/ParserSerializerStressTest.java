/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.serializer;

import de.rub.nds.tlsattacker.tests.IntegrationTest;
import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.tls.exceptions.ParserException;
import de.rub.nds.tlsattacker.tls.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.ApplicationMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.CertificateRequestMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.CertificateVerifyMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.DHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.DHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.ECDHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.ECDHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.HeartbeatMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.HelloRequestMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.HelloVerifyRequestMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.ProtocolMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.RSAClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.UnknownHandshakeMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.UnknownMessage;
import de.rub.nds.tlsattacker.tls.protocol.parser.AlertParser;
import de.rub.nds.tlsattacker.tls.protocol.parser.ApplicationMessageParser;
import de.rub.nds.tlsattacker.tls.protocol.parser.CertificateMessageParser;
import de.rub.nds.tlsattacker.tls.protocol.parser.CertificateRequestMessageParser;
import de.rub.nds.tlsattacker.tls.protocol.parser.CertificateVerifyMessageParser;
import de.rub.nds.tlsattacker.tls.protocol.parser.ChangeCipherSpecParser;
import de.rub.nds.tlsattacker.tls.protocol.parser.ClientHelloParser;
import de.rub.nds.tlsattacker.tls.protocol.parser.DHClientKeyExchangeParser;
import de.rub.nds.tlsattacker.tls.protocol.parser.DHEServerKeyExchangeParser;
import de.rub.nds.tlsattacker.tls.protocol.parser.ECDHClientKeyExchangeParser;
import de.rub.nds.tlsattacker.tls.protocol.parser.ECDHEServerKeyExchangeParser;
import de.rub.nds.tlsattacker.tls.protocol.parser.FinishedMessageParser;
import de.rub.nds.tlsattacker.tls.protocol.parser.HeartbeatMessageParser;
import de.rub.nds.tlsattacker.tls.protocol.parser.HelloRequestParser;
import de.rub.nds.tlsattacker.tls.protocol.parser.HelloVerifyRequestParser;
import de.rub.nds.tlsattacker.tls.protocol.parser.Parser;
import de.rub.nds.tlsattacker.tls.protocol.parser.ProtocolMessageParser;
import de.rub.nds.tlsattacker.tls.protocol.parser.RSAClientKeyExchangeParser;
import de.rub.nds.tlsattacker.tls.protocol.parser.ServerHelloDoneParser;
import de.rub.nds.tlsattacker.tls.protocol.parser.ServerHelloParser;
import de.rub.nds.tlsattacker.tls.protocol.parser.UnknownHandshakeMessageParser;
import de.rub.nds.tlsattacker.tls.protocol.parser.UnknownMessageParser;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import java.util.Random;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;
import org.junit.experimental.categories.Category;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class ParserSerializerStressTest {

    private static final Logger LOGGER = LogManager.getLogger(ParserSerializerStressTest.class);

    public ParserSerializerStressTest() {
    }

    @Before
    public void setUp() {
    }

    @Test
    @Category(IntegrationTest.class)
    public void testParser() {

        for (int i = 0; i < 100000; i++) {
            Random r = new Random(i);
            int random = r.nextInt(20);
            ProtocolMessage message = null;
            byte[] bytesToParse = null;
            try {
                int length = r.nextInt(10000);
                bytesToParse = new byte[length];
                r.nextBytes(bytesToParse);
                int start = r.nextInt(100);
                ProtocolMessageParser parser = getRandomParser(random, start, bytesToParse);
                message = parser.parse();
            } catch (ParserException E) {
                continue;
            }

            byte[] expected = message.getCompleteResultingMessage().getValue();
            ProtocolMessageSerializer serializer = getRandomSerializer(random, message);
            byte[] result = serializer.serialize();
            LOGGER.debug(message.toString());
            LOGGER.debug("Bytes to parse:\t" + ArrayConverter.bytesToHexString(bytesToParse, false));
            LOGGER.debug("Expected:\t" + ArrayConverter.bytesToHexString(expected, false));
            LOGGER.debug("Result:\t" + ArrayConverter.bytesToHexString(result, false));
            ProtocolMessageParser parser2 = getRandomParser(random, 0, result);
            ProtocolMessage serialized = parser2.parse();
            LOGGER.debug(serialized.toString());
            assertArrayEquals(result, expected);
            assertArrayEquals(serialized.getCompleteResultingMessage().getValue(), result);
        }
    }

    private ProtocolMessageParser getRandomParser(int random, int start, byte[] bytesToParse) {
        switch (random) {
            case 0:
                return new AlertParser(start, bytesToParse, ProtocolVersion.TLS12);
            case 1:
                return new ApplicationMessageParser(start, bytesToParse, ProtocolVersion.TLS12);
            case 2:
                return new CertificateMessageParser(start, bytesToParse, ProtocolVersion.TLS12);
            case 3:
                return new CertificateRequestMessageParser(start, bytesToParse, ProtocolVersion.TLS12);
            case 4:
                return new CertificateVerifyMessageParser(start, bytesToParse, ProtocolVersion.TLS12);
            case 5:
                return new ChangeCipherSpecParser(start, bytesToParse, ProtocolVersion.TLS12);
            case 6:
                return new ClientHelloParser(start, bytesToParse, ProtocolVersion.TLS12);
            case 7:
                return new DHClientKeyExchangeParser(start, bytesToParse, ProtocolVersion.TLS12);
            case 8:
                return new DHEServerKeyExchangeParser(start, bytesToParse, ProtocolVersion.TLS12);
            case 9:
                return new ECDHClientKeyExchangeParser(start, bytesToParse, ProtocolVersion.TLS12);
            case 10:
                return new ECDHEServerKeyExchangeParser(start, bytesToParse, ProtocolVersion.TLS12);
            case 11:
                return new FinishedMessageParser(start, bytesToParse, ProtocolVersion.TLS12);
            case 12:
                return new HeartbeatMessageParser(start, bytesToParse, ProtocolVersion.TLS12);
            case 13:
                return new HelloRequestParser(start, bytesToParse, ProtocolVersion.TLS12);
            case 14:
                return new HelloVerifyRequestParser(start, bytesToParse, ProtocolVersion.TLS12);
            case 15:
                return new RSAClientKeyExchangeParser(start, bytesToParse, ProtocolVersion.TLS12);
            case 16:
                return new ServerHelloDoneParser(start, bytesToParse, ProtocolVersion.TLS12);
            case 17:
                return new ServerHelloParser(start, bytesToParse, ProtocolVersion.TLS12);
            case 18:
                return new UnknownHandshakeMessageParser(start, bytesToParse, ProtocolVersion.TLS12);
            case 19:
                return new UnknownMessageParser(start, bytesToParse, ProtocolVersion.TLS12);
            default:
                throw new UnsupportedOperationException("Unsupported");
        }
    }

    private ProtocolMessageSerializer getRandomSerializer(int random, ProtocolMessage message) {
        switch (random) {
            case 0:
                return new AlertSerializer((AlertMessage) message);
            case 1:
                return new ApplicationMessageSerializer((ApplicationMessage) message);
            case 2:
                return new CertificateMessageSerializer((CertificateMessage) message);
            case 3:
                return new CertificateRequestMessageSerializer((CertificateRequestMessage) message);
            case 4:
                return new CertificateVerifyMessageSerializer((CertificateVerifyMessage) message);
            case 5:
                return new ChangeCipherSpecSerializer((ChangeCipherSpecMessage) message);
            case 6:
                return new ClientHelloSerializer((ClientHelloMessage) message);
            case 7:
                return new DHClientKeyExchangeSerializer((DHClientKeyExchangeMessage) message);
            case 8:
                return new DHEServerKeyExchangeSerializer((DHEServerKeyExchangeMessage) message);
            case 9:
                return new ECDHClientKeyExchangeSerializer((ECDHClientKeyExchangeMessage) message);
            case 10:
                return new ECDHEServerKeyExchangeSerializer((ECDHEServerKeyExchangeMessage) message);
            case 11:
                return new FinishedMessageSerializer((FinishedMessage) message);
            case 12:
                return new HeartbeatMessageSerializer((HeartbeatMessage) message);
            case 13:
                return new HelloRequestSerializer((HelloRequestMessage) message);
            case 14:
                return new HelloVerifyRequestSerializer((HelloVerifyRequestMessage) message);
            case 15:
                return new RSAClientKeyExchangeSerializer((RSAClientKeyExchangeMessage) message);
            case 16:
                return new ServerHelloDoneSerializer((ServerHelloDoneMessage) message);
            case 17:
                return new ServerHelloMessageSerializer((ServerHelloMessage) message);
            case 18:
                return new UnknownHandshakeMessageSerializer((UnknownHandshakeMessage) message);
            case 19:
                return new UnknownMessageSerializer((UnknownMessage) message);
            default:
                throw new UnsupportedOperationException("Unsupported");
        }
    }
}
