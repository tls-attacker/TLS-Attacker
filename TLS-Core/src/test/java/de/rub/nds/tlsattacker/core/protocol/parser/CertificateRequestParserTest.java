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
import de.rub.nds.tlsattacker.core.protocol.message.CertificateRequestMessage;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.io.ByteArrayInputStream;
import java.util.Arrays;
import java.util.Collection;
import static org.junit.Assert.*;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class CertificateRequestParserTest {

    // private static byte[] SSL3_CERTREQ_MSG =
    // ArrayConverter.hexStringToByteArray("0d000006030102400000");
    private static final byte[] RSA_DSS_ECDSA_TYPES = ArrayConverter.hexStringToByteArray("010240");

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return Arrays.asList(new Object[][] { {
            ArrayConverter.hexStringToByteArray(
                "03010240001e0601060206030501050205030401040204030301030203030201020202030000"),
            3, RSA_DSS_ECDSA_TYPES, 30,
            ArrayConverter.hexStringToByteArray("060106020603050105020503040104020403030103020303020102020203"), 0,
            null, ProtocolVersion.TLS12 } });
        // TestData is correct, however Certificate request and other
        // Client-Authentication related messages are not yet supported for
        // TLS-Version < 1.2
    }

    private byte[] message;
    private int certTypesCount;
    private byte[] certTypes;
    private int sigHashAlgsLength;
    private byte[] sigHashAlgs;
    private int distinguishedNamesLength;
    private byte[] distinguishedNames;
    private ProtocolVersion version;
    private final Config config = Config.createConfig();

    public CertificateRequestParserTest(byte[] message, int certTypesCount, byte[] certTypes, int sigHashAlgsLength,
        byte[] sigHashAlgs, int distinguishedNamesLength, byte[] distinguishedNames, ProtocolVersion version) {
        this.message = message;
        this.certTypesCount = certTypesCount;
        this.certTypes = certTypes;
        this.sigHashAlgsLength = sigHashAlgsLength;
        this.sigHashAlgs = sigHashAlgs;
        this.distinguishedNamesLength = distinguishedNamesLength;
        this.distinguishedNames = distinguishedNames;
        this.version = version;
    }

    /**
     * Test of parse method, of class CertificateRequestParser.
     */
    @Test
    public void testParse() {
        TlsContext tlsContext = new TlsContext(config);
        tlsContext.setTalkingConnectionEndType(ConnectionEndType.SERVER);
        CertificateRequestParser parser =
            new CertificateRequestParser(new ByteArrayInputStream(message), version, tlsContext);
        CertificateRequestMessage msg = new CertificateRequestMessage();
        parser.parse(msg);
        assertTrue(msg.getClientCertificateTypesCount().getValue() == certTypesCount);
        assertArrayEquals(certTypes, msg.getClientCertificateTypes().getValue());
        assertTrue(msg.getSignatureHashAlgorithmsLength().getValue() == sigHashAlgsLength);
        assertArrayEquals(sigHashAlgs, msg.getSignatureHashAlgorithms().getValue());
        assertTrue(msg.getDistinguishedNamesLength().getValue() == distinguishedNamesLength);
        if (distinguishedNamesLength == 0) {
            assertNull(msg.getDistinguishedNames());
        } else {
            assertArrayEquals(distinguishedNames, msg.getDistinguishedNames().getValue());
        }
    }

}
