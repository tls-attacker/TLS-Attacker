/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.serializer;

import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateStatusMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.CertificateStatusMessageParserTest;
import java.util.Collection;
import static org.junit.Assert.assertArrayEquals;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class CertificateStatusSerializerTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return CertificateStatusMessageParserTest.generateData();
    }

    private byte[] message;
    private int certificateStatusType;
    private int ocspResponseLength;
    private byte[] ocspResponseBytes;
    private ProtocolVersion version;

    public CertificateStatusSerializerTest(byte[] message, int certificateStatusType, int ocspResponseLength,
        byte[] ocspResponseBytes, ProtocolVersion version) {
        this.message = message;
        this.certificateStatusType = certificateStatusType;
        this.ocspResponseLength = ocspResponseLength;
        this.ocspResponseBytes = ocspResponseBytes;
        this.version = version;
    }

    @Test
    public void testserializeProtocolMessageContent() {
        CertificateStatusMessage message = new CertificateStatusMessage();
        message.setCertificateStatusType(certificateStatusType);
        message.setOcspResponseLength(ocspResponseLength);
        message.setOcspResponseBytes(ocspResponseBytes);
        CertificateStatusSerializer serializer = new CertificateStatusSerializer(message, version);
        assertArrayEquals(this.message, serializer.serializeProtocolMessageContent());
    }
}
