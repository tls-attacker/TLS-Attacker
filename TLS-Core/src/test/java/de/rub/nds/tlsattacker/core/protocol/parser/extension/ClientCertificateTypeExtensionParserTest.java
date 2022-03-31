/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CertificateType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ClientCertificateTypeExtensionMessage;
import java.io.ByteArrayInputStream;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class ClientCertificateTypeExtensionParserTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return Arrays.asList(new Object[][] {
            { ArrayConverter.hexStringToByteArray("00"), null, Arrays.asList(CertificateType.X509), false },
            { ArrayConverter.hexStringToByteArray("0100"), 1, Arrays.asList(CertificateType.X509), true },
            { ArrayConverter.hexStringToByteArray("020100"), 2,
                Arrays.asList(CertificateType.OPEN_PGP, CertificateType.X509), true } });
    }

    private final byte[] expectedBytes;
    private final Integer certificateTypesLength;
    private final List<CertificateType> certificateTypes;
    private final boolean isClientState;
    private ClientCertificateTypeExtensionParser parser;
    private ClientCertificateTypeExtensionMessage msg;

    public ClientCertificateTypeExtensionParserTest(byte[] expectedBytes, Integer certificateTypesLength,
        List<CertificateType> certificateTypes, boolean isClientState) {
        this.expectedBytes = expectedBytes;
        this.certificateTypesLength = certificateTypesLength;
        this.certificateTypes = certificateTypes;
        this.isClientState = isClientState;
    }

    @Before
    public void setUp() {
        parser =
            new ClientCertificateTypeExtensionParser(new ByteArrayInputStream(expectedBytes), Config.createConfig());
    }

    @Test
    public void testParse() {
        msg = new ClientCertificateTypeExtensionMessage();
        parser.parse(msg);

        if (certificateTypesLength != null) {
            assertEquals(certificateTypesLength, msg.getCertificateTypesLength().getValue());
        } else {
            assertNull(msg.getCertificateTypesLength());
        }
        assertArrayEquals(CertificateType.toByteArray(certificateTypes), msg.getCertificateTypes().getValue());
    }

}
