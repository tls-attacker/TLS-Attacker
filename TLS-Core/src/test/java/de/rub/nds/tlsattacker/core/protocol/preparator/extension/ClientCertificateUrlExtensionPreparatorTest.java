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

import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ClientCertificateUrlExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.ClientCertificateUrlExtensionSerializer;
import org.junit.jupiter.api.Test;

public class ClientCertificateUrlExtensionPreparatorTest
        extends AbstractExtensionMessagePreparatorTest<
                ClientCertificateUrlExtensionMessage,
                ClientCertificateUrlExtensionSerializer,
                ClientCertificateUrlExtensionPreparator> {

    public ClientCertificateUrlExtensionPreparatorTest() {
        super(
                ClientCertificateUrlExtensionMessage::new,
                ClientCertificateUrlExtensionSerializer::new,
                ClientCertificateUrlExtensionPreparator::new);
    }

    @Test
    @Override
    public void testPrepare() {
        preparator.prepare();

        assertArrayEquals(
                ExtensionType.CLIENT_CERTIFICATE_URL.getValue(),
                message.getExtensionType().getValue());
        assertEquals(0, (long) message.getExtensionLength().getValue());
    }
}
