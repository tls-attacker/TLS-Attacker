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
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
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
            { ArrayConverter.hexStringToByteArray("00"), null, Arrays.asList(CertificateType.X509),
                ConnectionEndType.SERVER },
            { ArrayConverter.hexStringToByteArray("0100"), 1, Arrays.asList(CertificateType.X509),
                ConnectionEndType.CLIENT },
            { ArrayConverter.hexStringToByteArray("020100"), 2,
                Arrays.asList(CertificateType.OPEN_PGP, CertificateType.X509), ConnectionEndType.CLIENT } });
    }

    private final byte[] expectedBytes;
    private final Integer certificateTypesLength;
    private final List<CertificateType> certificateTypes;
    private final ConnectionEndType talkingConnectionEndType;
    private ClientCertificateTypeExtensionParser parser;
    private ClientCertificateTypeExtensionMessage msg;
    private final Config config = Config.createConfig();

    public ClientCertificateTypeExtensionParserTest(byte[] expectedBytes, Integer certificateTypesLength,
        List<CertificateType> certificateTypes, ConnectionEndType talkingConnectionEndType) {
        this.expectedBytes = expectedBytes;
        this.certificateTypesLength = certificateTypesLength;
        this.certificateTypes = certificateTypes;
        this.talkingConnectionEndType = talkingConnectionEndType;
    }

    @Before
    public void setUp() {
        TlsContext tlsContext = new TlsContext(config);
        tlsContext.setTalkingConnectionEndType(talkingConnectionEndType);
        parser = new ClientCertificateTypeExtensionParser(new ByteArrayInputStream(expectedBytes), tlsContext);
    }

    @Test
    public void testParseExtensionMessageContent() {
        msg = new ClientCertificateTypeExtensionMessage();
        parser.parse(msg);

        if (talkingConnectionEndType == ConnectionEndType.CLIENT) {
            assertEquals(certificateTypesLength, msg.getCertificateTypesLength().getValue());
        } else {
            assertNull(msg.getCertificateTypesLength());
        }
        assertArrayEquals(CertificateType.toByteArray(certificateTypes), msg.getCertificateTypes().getValue());
    }

}
