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
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.io.ByteArrayInputStream;
import java.util.Arrays;
import java.util.Collection;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertTrue;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class CertificateRequestTls13ParserTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return Arrays.asList(new Object[][] { { ArrayConverter.hexStringToByteArray("01020000"), 1,
            ArrayConverter.hexStringToByteArray("02"), new byte[0], ProtocolVersion.TLS13 } });
    }

    private byte[] message;
    private HandshakeMessageType type;
    private int certificateRequestContextLength;
    private byte[] certificateRequestContext;
    private int extensionLength;
    private byte[] extensionBytes;
    private ProtocolVersion version;

    public CertificateRequestTls13ParserTest(byte[] message, int certificateRequestContextLength,
        byte[] certificateRequestContext, byte[] extensionBytes, ProtocolVersion version) {
        this.message = message;
        this.certificateRequestContextLength = certificateRequestContextLength;
        this.certificateRequestContext = certificateRequestContext;
        this.extensionBytes = extensionBytes;
        this.version = version;
    }

    @Test
    public void testParse() {
        CertificateRequestParser parser = new CertificateRequestParser(new ByteArrayInputStream(message), version,
            new TlsContext(new Config()), ConnectionEndType.SERVER);
        CertificateRequestMessage msg = new CertificateRequestMessage();
        parser.parse(msg);
        assertTrue(msg.getCertificateRequestContextLength().getValue() == certificateRequestContextLength);
        assertArrayEquals(msg.getCertificateRequestContext().getValue(), certificateRequestContext);
        assertTrue(msg.getExtensionsLength().getValue() == extensionLength);
        assertArrayEquals(msg.getExtensionBytes().getValue(), extensionBytes);
    }
}
