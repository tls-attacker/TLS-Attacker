/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.serializer;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.exceptions.ParserException;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ApplicationMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateRequestMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateVerifyMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.DHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.DHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ECDHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ECDHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HeartbeatMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HelloRequestMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HelloVerifyRequestMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.RSAClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.UnknownHandshakeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.UnknownMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.AlertParser;
import de.rub.nds.tlsattacker.core.protocol.parser.ApplicationMessageParser;
import de.rub.nds.tlsattacker.core.protocol.parser.CertificateMessageParser;
import de.rub.nds.tlsattacker.core.protocol.parser.CertificateRequestParser;
import de.rub.nds.tlsattacker.core.protocol.parser.CertificateVerifyParser;
import de.rub.nds.tlsattacker.core.protocol.parser.ChangeCipherSpecParser;
import de.rub.nds.tlsattacker.core.protocol.parser.ClientHelloParser;
import de.rub.nds.tlsattacker.core.protocol.parser.DHClientKeyExchangeParser;
import de.rub.nds.tlsattacker.core.protocol.parser.DHEServerKeyExchangeParser;
import de.rub.nds.tlsattacker.core.protocol.parser.ECDHClientKeyExchangeParser;
import de.rub.nds.tlsattacker.core.protocol.parser.ECDHEServerKeyExchangeParser;
import de.rub.nds.tlsattacker.core.protocol.parser.FinishedParser;
import de.rub.nds.tlsattacker.core.protocol.parser.HeartbeatMessageParser;
import de.rub.nds.tlsattacker.core.protocol.parser.HelloRequestParser;
import de.rub.nds.tlsattacker.core.protocol.parser.HelloVerifyRequestParser;
import de.rub.nds.tlsattacker.core.protocol.parser.ProtocolMessageParser;
import de.rub.nds.tlsattacker.core.protocol.parser.RSAClientKeyExchangeParser;
import de.rub.nds.tlsattacker.core.protocol.parser.ServerHelloDoneParser;
import de.rub.nds.tlsattacker.core.protocol.parser.ServerHelloParser;
import de.rub.nds.tlsattacker.core.protocol.parser.UnknownHandshakeParser;
import de.rub.nds.tlsattacker.core.protocol.parser.UnknownParser;
import de.rub.nds.tlsattacker.util.tests.IntegrationTests;
import java.util.Random;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import static org.junit.Assert.*;
import org.junit.Test;
import org.junit.experimental.categories.Category;

public class ParserSerializerStressTest {

    private static final Logger LOGGER = LogManager.getLogger();

    @Test
    @Category(IntegrationTests.class)
    public void testParser() {

        for (int i = 0; i < 1000; i++) {
            Random r = new Random(i);
            int random = r.nextInt(20);
            ProtocolMessage message = null;
            byte[] bytesToParse = null;
            try {
                int length = r.nextInt(1000);
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
                return new CertificateRequestParser(start, bytesToParse, ProtocolVersion.TLS12);
            case 4:
                return new CertificateVerifyParser(start, bytesToParse, ProtocolVersion.TLS12);
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
                return new FinishedParser(start, bytesToParse, ProtocolVersion.TLS12);
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
                return new UnknownHandshakeParser(start, bytesToParse, ProtocolVersion.TLS12);
            case 19:
                return new UnknownParser(start, bytesToParse, ProtocolVersion.TLS12);
            default:
                throw new UnsupportedOperationException("Unsupported");
        }
    }

    private ProtocolMessageSerializer getRandomSerializer(int random, ProtocolMessage message) {
        switch (random) {
            case 0:
                return new AlertSerializer((AlertMessage) message, ProtocolVersion.TLS12);
            case 1:
                return new ApplicationMessageSerializer((ApplicationMessage) message, ProtocolVersion.TLS12);
            case 2:
                return new CertificateMessageSerializer((CertificateMessage) message, ProtocolVersion.TLS12);
            case 3:
                return new CertificateRequestSerializer((CertificateRequestMessage) message, ProtocolVersion.TLS12);
            case 4:
                return new CertificateVerifySerializer((CertificateVerifyMessage) message, ProtocolVersion.TLS12);
            case 5:
                return new ChangeCipherSpecSerializer((ChangeCipherSpecMessage) message, ProtocolVersion.TLS12);
            case 6:
                return new ClientHelloSerializer((ClientHelloMessage) message, ProtocolVersion.TLS12);
            case 7:
                return new DHClientKeyExchangeSerializer((DHClientKeyExchangeMessage) message, ProtocolVersion.TLS12);
            case 8:
                return new DHEServerKeyExchangeSerializer((DHEServerKeyExchangeMessage) message, ProtocolVersion.TLS12);
            case 9:
                return new ECDHClientKeyExchangeSerializer((ECDHClientKeyExchangeMessage) message,
                        ProtocolVersion.TLS12);
            case 10:
                return new ECDHEServerKeyExchangeSerializer((ECDHEServerKeyExchangeMessage) message,
                        ProtocolVersion.TLS12);
            case 11:
                return new FinishedSerializer((FinishedMessage) message, ProtocolVersion.TLS12);
            case 12:
                return new HeartbeatMessageSerializer((HeartbeatMessage) message, ProtocolVersion.TLS12);
            case 13:
                return new HelloRequestSerializer((HelloRequestMessage) message, ProtocolVersion.TLS12);
            case 14:
                return new HelloVerifyRequestSerializer((HelloVerifyRequestMessage) message, ProtocolVersion.TLS12);
            case 15:
                return new RSAClientKeyExchangeSerializer((RSAClientKeyExchangeMessage) message, ProtocolVersion.TLS12);
            case 16:
                return new ServerHelloDoneSerializer((ServerHelloDoneMessage) message, ProtocolVersion.TLS12);
            case 17:
                return new ServerHelloSerializer((ServerHelloMessage) message, ProtocolVersion.TLS12);
            case 18:
                return new UnknownHandshakeSerializer((UnknownHandshakeMessage) message, ProtocolVersion.TLS12);
            case 19:
                return new UnknownSerializer((UnknownMessage) message, ProtocolVersion.TLS12);
            default:
                throw new UnsupportedOperationException("Unsupported");
        }
    }
}
