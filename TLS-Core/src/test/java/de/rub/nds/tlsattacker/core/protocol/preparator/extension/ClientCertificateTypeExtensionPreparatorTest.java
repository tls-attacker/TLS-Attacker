/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import de.rub.nds.tlsattacker.core.constants.CertificateType;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ClientCertificateTypeExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.ClientCertificateTypeExtensionSerializer;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;

public class ClientCertificateTypeExtensionPreparatorTest
        extends AbstractExtensionMessagePreparatorTest<
                ClientCertificateTypeExtensionMessage,
                ClientCertificateTypeExtensionSerializer,
                ClientCertificateTypeExtensionPreparator> {

    public ClientCertificateTypeExtensionPreparatorTest() {
        super(
                ClientCertificateTypeExtensionMessage::new,
                ClientCertificateTypeExtensionSerializer::new,
                ClientCertificateTypeExtensionPreparator::new);
    }

    @Test
    @Override
    public void testPrepare() {
        List<CertificateType> certList =
                Arrays.asList(CertificateType.OPEN_PGP, CertificateType.X509);
        context.getConfig().setClientCertificateTypeDesiredTypes(certList);

        preparator.prepare();

        assertArrayEquals(
                ExtensionType.CLIENT_CERTIFICATE_TYPE.getValue(),
                message.getExtensionType().getValue());
        assertEquals(3, message.getExtensionLength().getValue());
        assertArrayEquals(
                CertificateType.toByteArray(certList), message.getCertificateTypes().getValue());
        assertEquals(2, message.getCertificateTypesLength().getValue());
    }
}
