/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import de.rub.nds.tlsattacker.core.constants.CertificateType;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ServerCertificateTypeExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.ServerCertificateTypeExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.util.Arrays;
import java.util.List;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import org.junit.Before;
import org.junit.Test;

public class ServerCertificateTypeExtensionPreparatorTest {

    private TlsContext context;
    private ServerCertificateTypeExtensionPreparator preparator;
    private ServerCertificateTypeExtensionMessage msg;
    private final List<CertificateType> certList = Arrays.asList(CertificateType.OPEN_PGP, CertificateType.X509);
    private final int extensionLength = 3;
    private final int cerListLength = 2;

    @Before
    public void setUp() {
        context = new TlsContext();
        msg = new ServerCertificateTypeExtensionMessage();
        preparator = new ServerCertificateTypeExtensionPreparator(context.getChooser(), msg,
                new ServerCertificateTypeExtensionSerializer(msg));
    }

    @Test
    public void testPreparator() {
        context.getConfig().setServerCertificateTypeDesiredTypes(certList);

        preparator.prepare();

        assertArrayEquals(ExtensionType.SERVER_CERTIFICATE_TYPE.getValue(), msg.getExtensionType().getValue());
        assertEquals(extensionLength, (long) msg.getExtensionLength().getValue());
        assertArrayEquals(CertificateType.toByteArray(certList), msg.getCertificateTypes().getValue());
        assertEquals(cerListLength, (long) msg.getCertificateTypesLength().getValue());
    }

}
