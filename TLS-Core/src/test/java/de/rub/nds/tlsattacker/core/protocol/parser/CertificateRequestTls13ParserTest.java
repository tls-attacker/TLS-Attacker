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
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateRequestMessage;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.util.Arrays;
import java.util.Collection;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertTrue;

@RunWith(Parameterized.class)
public class CertificateRequestTls13ParserTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return Arrays.asList(new Object[][] {
            { ArrayConverter.hexStringToByteArray("0d00000401020000"), HandshakeMessageType.CERTIFICATE_REQUEST, 1,
                ArrayConverter.hexStringToByteArray("02"), 0, new byte[0], ProtocolVersion.TLS13 } });
    }

    private byte[] message;
    private HandshakeMessageType type;
    private int certificateRequestContextLength;
    private byte[] certificateRequestContext;
    private int extensionLength;
    private byte[] extensionBytes;
    private ProtocolVersion version;

    public CertificateRequestTls13ParserTest(byte[] message, HandshakeMessageType type,
        int certificateRequestContextLength, byte[] certificateRequestContext, int extensionLength,
        byte[] extensionBytes, ProtocolVersion version) {
        this.message = message;
        this.type = type;
        this.certificateRequestContextLength = certificateRequestContextLength;
        this.certificateRequestContext = certificateRequestContext;
        this.extensionLength = extensionLength;
        this.extensionBytes = extensionBytes;
        this.version = version;
    }

    @Test
    public void testParse() {
        CertificateRequestParser parser = new CertificateRequestParser(0, message, version, Config.createConfig());
        CertificateRequestMessage msg = parser.parse();
        assertArrayEquals(message, msg.getCompleteResultingMessage().getValue());
        assertTrue(msg.getCertificateRequestContextLength().getValue() == certificateRequestContextLength);
        assertArrayEquals(msg.getCertificateRequestContext().getValue(), certificateRequestContext);
        assertTrue(msg.getExtensionsLength().getValue() == extensionLength);
        assertArrayEquals(msg.getExtensionBytes().getValue(), extensionBytes);
    }
}
