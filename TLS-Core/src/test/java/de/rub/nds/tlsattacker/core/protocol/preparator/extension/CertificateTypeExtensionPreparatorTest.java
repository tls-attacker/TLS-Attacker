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
import de.rub.nds.tlsattacker.core.protocol.message.extension.CertificateTypeExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.CertificateTypeExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.util.Arrays;
import java.util.List;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import org.junit.Before;
import org.junit.Test;

public class CertificateTypeExtensionPreparatorTest {

    private TlsContext context;
    private CertificateTypeExtensionPreparator preparator;
    private CertificateTypeExtensionMessage msg;
    private final List<CertificateType> certList = Arrays.asList(CertificateType.OPEN_PGP, CertificateType.X509);
    private final int extensionLength = 3;
    private final int cerListLength = 2;

    @Before
    public void setUp() {
        context = new TlsContext();
        msg = new CertificateTypeExtensionMessage();
        preparator = new CertificateTypeExtensionPreparator(context.getChooser(), msg,
                new CertificateTypeExtensionSerializer(msg));
    }

    @Test
    public void testPreparator() {
        context.getConfig().setCertificateTypeDesiredTypes(certList);

        preparator.prepare();

        assertArrayEquals(ExtensionType.CERT_TYPE.getValue(), msg.getExtensionType().getValue());
        assertEquals(extensionLength, (long) msg.getExtensionLength().getValue());
        assertArrayEquals(CertificateType.toByteArray(certList), msg.getCertificateTypes().getValue());
        assertEquals(cerListLength, (long) msg.getCertificateTypesLength().getValue());
    }

}
