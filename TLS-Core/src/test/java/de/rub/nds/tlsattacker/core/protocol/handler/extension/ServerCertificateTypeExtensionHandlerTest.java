/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.tlsattacker.core.constants.CertificateType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ServerCertificateTypeExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.ServerCertificateTypeExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.ServerCertificateTypeExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.ServerCertificateTypeExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.util.Arrays;
import java.util.List;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.Test;

public class ServerCertificateTypeExtensionHandlerTest {
    private final List<CertificateType> certList = Arrays.asList(CertificateType.OPEN_PGP, CertificateType.X509,
            CertificateType.RAW_PUBLIC_KEY);
    private ServerCertificateTypeExtensionHandler handler;
    private TlsContext context;

    @Before
    public void setUp() {
        context = new TlsContext();
        handler = new ServerCertificateTypeExtensionHandler(context);
    }

    @Test
    public void testAdjustTLSContext() {
        ServerCertificateTypeExtensionMessage msg = new ServerCertificateTypeExtensionMessage();
        msg.setCertificateTypes(CertificateType.toByteArray(certList));

        handler.adjustTLSContext(msg);

        assertThat(certList, is(context.getServerCertificateTypeDesiredTypes()));
    }

    @Test
    public void testGetParser() {
        assertTrue(handler.getParser(new byte[0], 0) instanceof ServerCertificateTypeExtensionParser);
    }

    @Test
    public void testGetPreparator() {
        assertTrue(handler.getPreparator(new ServerCertificateTypeExtensionMessage()) instanceof ServerCertificateTypeExtensionPreparator);
    }

    @Test
    public void testGetSerializer() {
        assertTrue(handler.getSerializer(new ServerCertificateTypeExtensionMessage()) instanceof ServerCertificateTypeExtensionSerializer);
    }
}
