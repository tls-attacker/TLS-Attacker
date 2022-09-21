/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.exceptions.ParserException;
import de.rub.nds.tlsattacker.core.protocol.message.*;
import de.rub.nds.tlsattacker.core.protocol.parser.*;
import de.rub.nds.tlsattacker.core.protocol.serializer.*;
import de.rub.nds.tlsattacker.util.tests.TestCategories;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.util.Random;

public class ParserSerializerIT {

    private static final Logger LOGGER = LogManager.getLogger();
    private final Config config = Config.createConfig();

    @Test
    @Tag(TestCategories.INTEGRATION_TEST)
    public void testParser() {
        Random r = new Random(42);
        for (int i = 0; i < 10000; i++) {
            int random = r.nextInt(20);
            ProtocolMessage message = null;
            byte[] bytesToParse = null;
            try {
                int length = r.nextInt(1000);
                bytesToParse = new byte[length];
                r.nextBytes(bytesToParse);
                int start = r.nextInt(100);
                ProtocolMessageParser<? extends ProtocolMessage> parser = getRandomParser(random, start, bytesToParse);
                message = parser.parse();
            } catch (ParserException E) {
                continue;
            }

            byte[] expected = message.getCompleteResultingMessage().getValue();
            ProtocolMessageSerializer<? extends ProtocolMessage> serializer = getRandomSerializer(random, message);
            byte[] result = serializer.serialize();
            LOGGER.debug(message.toString());
            LOGGER.debug("Bytes to parse:\t" + ArrayConverter.bytesToHexString(bytesToParse, false));
            LOGGER.debug("Expected:\t" + ArrayConverter.bytesToHexString(expected, false));
            LOGGER.debug("Result:\t" + ArrayConverter.bytesToHexString(result, false));
            ProtocolMessageParser<? extends ProtocolMessage> parser2 = getRandomParser(random, 0, result);
            ProtocolMessage serialized = parser2.parse();
            LOGGER.debug(serialized.toString());
            assertArrayEquals(result, expected);
            assertArrayEquals(serialized.getCompleteResultingMessage().getValue(), result);
        }
    }

    private ProtocolMessageParser<? extends ProtocolMessage> getRandomParser(int random, int start,
        byte[] bytesToParse) {
        switch (random) {
            case 0:
                return new AlertParser(start, bytesToParse, ProtocolVersion.TLS12, config);
            case 1:
                return new ApplicationMessageParser(start, bytesToParse, ProtocolVersion.TLS12, config);
            case 2:
                return new CertificateMessageParser(start, bytesToParse, ProtocolVersion.TLS12, config);
            case 3:
                return new CertificateRequestParser(start, bytesToParse, ProtocolVersion.TLS12, config);
            case 4:
                return new CertificateVerifyParser(start, bytesToParse, ProtocolVersion.TLS12, config);
            case 5:
                return new ChangeCipherSpecParser(start, bytesToParse, ProtocolVersion.TLS12, config);
            case 6:
                return new ClientHelloParser(start, bytesToParse, ProtocolVersion.TLS12, config);
            case 7:
                return new DHClientKeyExchangeParser<>(start, bytesToParse, ProtocolVersion.TLS12, config);
            case 8:
                return new DHEServerKeyExchangeParser<>(start, bytesToParse, ProtocolVersion.TLS12, config);
            case 9:
                return new ECDHClientKeyExchangeParser<>(start, bytesToParse, ProtocolVersion.TLS12, config);
            case 10:
                return new ECDHEServerKeyExchangeParser<>(start, bytesToParse, ProtocolVersion.TLS12, config);
            case 11:
                return new FinishedParser(start, bytesToParse, ProtocolVersion.TLS12, config);
            case 12:
                return new HeartbeatMessageParser(start, bytesToParse, ProtocolVersion.TLS12, config);
            case 13:
                return new HelloRequestParser(start, bytesToParse, ProtocolVersion.TLS12, config);
            case 14:
                return new HelloVerifyRequestParser(start, bytesToParse, ProtocolVersion.TLS12, config);
            case 15:
                return new RSAClientKeyExchangeParser<>(start, bytesToParse, ProtocolVersion.TLS12, config);
            case 16:
                return new ServerHelloDoneParser(start, bytesToParse, ProtocolVersion.TLS12, config);
            case 17:
                return new ServerHelloParser(start, bytesToParse, ProtocolVersion.TLS12, config);
            case 18:
                return new UnknownHandshakeParser(start, bytesToParse, ProtocolVersion.TLS12, config);
            case 19:
                return new UnknownMessageParser(start, bytesToParse, ProtocolVersion.TLS12, ProtocolMessageType.UNKNOWN,
                    config);
            default:
                throw new UnsupportedOperationException("Unsupported");
        }
    }

    private ProtocolMessageSerializer<? extends ProtocolMessage> getRandomSerializer(int random,
        ProtocolMessage message) {
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
                return new DHClientKeyExchangeSerializer<>((DHClientKeyExchangeMessage) message, ProtocolVersion.TLS12);
            case 8:
                return new DHEServerKeyExchangeSerializer<>((DHEServerKeyExchangeMessage) message,
                    ProtocolVersion.TLS12);
            case 9:
                return new ECDHClientKeyExchangeSerializer<>((ECDHClientKeyExchangeMessage) message,
                    ProtocolVersion.TLS12);
            case 10:
                return new ECDHEServerKeyExchangeSerializer<>((ECDHEServerKeyExchangeMessage) message,
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
                return new RSAClientKeyExchangeSerializer<>((RSAClientKeyExchangeMessage) message,
                    ProtocolVersion.TLS12);
            case 16:
                return new ServerHelloDoneSerializer((ServerHelloDoneMessage) message, ProtocolVersion.TLS12);
            case 17:
                return new ServerHelloSerializer((ServerHelloMessage) message, ProtocolVersion.TLS12);
            case 18:
                return new UnknownHandshakeSerializer((UnknownHandshakeMessage) message, ProtocolVersion.TLS12);
            case 19:
                return new UnknownMessageSerializer((UnknownMessage) message, ProtocolVersion.TLS12);
            default:
                throw new UnsupportedOperationException("Unsupported");
        }
    }
}
