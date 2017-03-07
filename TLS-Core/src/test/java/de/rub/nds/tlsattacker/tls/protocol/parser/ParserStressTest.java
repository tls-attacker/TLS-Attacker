/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.parser;

import de.rub.nds.tlsattacker.tests.IntegrationTest;
import de.rub.nds.tlsattacker.tls.exceptions.ParserException;
import de.rub.nds.tlsattacker.tls.protocol.message.ServerHelloMessage;
import java.util.Random;
import org.junit.Test;
import org.junit.experimental.categories.Category;

/**
 * This test makes sure that the parsers dont throw other exceptions other than
 * parser exceptions Not every message is always parsable, but the parser should
 * be able to deal with everything
 *
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class ParserStressTest {

    @Test
    @Category(IntegrationTest.class)
    public void testParser() {
        for (int i = 0; i < 100000; i++) {
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
                return new AlertParser(start, bytesToParse);
            case 1:
                return new ApplicationMessageParser(start, bytesToParse);
            case 2:
                return new CertificateMessageParser(start, bytesToParse);
            case 3:
                return new CertificateRequestMessageParser(start, bytesToParse);
            case 4:
                return new CertificateVerifyMessageParser(start, bytesToParse);
            case 5:
                return new ChangeCipherSpecParser(start, bytesToParse);
            case 6:
                return new ClientHelloParser(start, bytesToParse);
            case 7:
                return new DHClientKeyExchangeParser(start, bytesToParse);
            case 8:
                return new DHEServerKeyExchangeParser(start, bytesToParse);
            case 9:
                return new ECDHClientKeyExchangeParser(start, bytesToParse);
            case 10:
                return new ECDHEServerKeyExchangeParser(start, bytesToParse);
            case 11:
                return new FinishedMessageParser(start, bytesToParse);
            case 12:
                return new HeartbeatMessageParser(start, bytesToParse);
            case 13:
                return new HelloRequestParser(start, bytesToParse);
            case 14:
                return new HelloVerifyRequestParser(start, bytesToParse);
            case 15:
                return new RSAClientKeyExchangeParser(start, bytesToParse);
            case 16:
                return new ServerHelloDoneParser(start, bytesToParse);
            case 17:
                return new ServerHelloParser(start, bytesToParse);
            case 18:
                return new UnknownHandshakeMessageParser(start, bytesToParse);
            case 19:
                return new UnknownMessageParser(start, bytesToParse);
            default:
                throw new UnsupportedOperationException("Unsupported");
        }
    }
}
