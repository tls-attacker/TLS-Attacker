/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.parser;

import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.exceptions.ParserException;
import de.rub.nds.tlsattacker.util.tests.IntegrationTests;
import java.util.Random;
import org.junit.Test;
import org.junit.experimental.categories.Category;

/**
 * This test makes sure that the parsers dont throw other exceptions other than
 * parser exceptions Not every message is always parsable, but the parser should
 * be able to deal with everything
 */
public class ParserStressTest {

    @Test
    @Category(IntegrationTests.class)
    public void testParser() {
        for (int i = 0; i < 10000; i++) {
            Random r = new Random(i);
            try {
                int length = r.nextInt(10000);
                byte[] bytesToParse = new byte[length];
                r.nextBytes(bytesToParse);
                int start = r.nextInt(100);
                if (bytesToParse.length > start) {
                    bytesToParse[start] = 0x02;
                }
                Parser parser = getRandomParser(r, start, bytesToParse);
                parser.parse();

            } catch (ParserException E) {
            }
        }
    }

    private Parser getRandomParser(Random r, int start, byte[] bytesToParse) {
        switch (r.nextInt(20)) {
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
}
