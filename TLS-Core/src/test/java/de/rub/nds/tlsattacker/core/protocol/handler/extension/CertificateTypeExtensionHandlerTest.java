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
import de.rub.nds.tlsattacker.core.protocol.message.extension.CertificateTypeExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.CertificateTypeExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.CertificateTypeExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.CertificateTypeExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.util.Arrays;
import java.util.List;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.Test;

public class CertificateTypeExtensionHandlerTest {
    private final List<CertificateType> certList = Arrays.asList(CertificateType.OPEN_PGP, CertificateType.X509);
    private CertificateTypeExtensionHandler handler;
    private TlsContext context;

    @Before
    public void setUp() {
        context = new TlsContext();
        handler = new CertificateTypeExtensionHandler(context);
    }

    @Test
    public void testAdjustTLSContext() {
        CertificateTypeExtensionMessage msg = new CertificateTypeExtensionMessage();
        msg.setCertificateTypes(CertificateType.toByteArray(certList));

        handler.adjustTLSContext(msg);

        assertThat(certList, is(context.getCertificateTypeDesiredTypes()));
    }

    @Test
    public void testGetParser() {
        assertTrue(handler.getParser(new byte[0], 0) instanceof CertificateTypeExtensionParser);
    }

    @Test
    public void testGetPreparator() {
        assertTrue(handler.getPreparator(new CertificateTypeExtensionMessage()) instanceof CertificateTypeExtensionPreparator);
    }

    @Test
    public void testGetSerializer() {
        assertTrue(handler.getSerializer(new CertificateTypeExtensionMessage()) instanceof CertificateTypeExtensionSerializer);
    }
}
