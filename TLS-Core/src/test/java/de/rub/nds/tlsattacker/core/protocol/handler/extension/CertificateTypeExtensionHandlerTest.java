/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import static org.junit.jupiter.api.Assertions.assertEquals;

import de.rub.nds.tlsattacker.core.constants.CertificateType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.CertificateTypeExtensionMessage;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;

public class CertificateTypeExtensionHandlerTest
        extends AbstractExtensionMessageHandlerTest<
                CertificateTypeExtensionMessage, CertificateTypeExtensionHandler> {
    private final List<CertificateType> certList =
            Arrays.asList(CertificateType.OPEN_PGP, CertificateType.X509);

    public CertificateTypeExtensionHandlerTest() {
        super(CertificateTypeExtensionMessage::new, CertificateTypeExtensionHandler::new);
    }

    @Test
    @Override
    public void testadjustTLSExtensionContext() {
        CertificateTypeExtensionMessage msg = new CertificateTypeExtensionMessage();
        msg.setCertificateTypes(CertificateType.toByteArray(certList));

        handler.adjustContext(msg);

        assertEquals(certList, context.getCertificateTypeDesiredTypes());
    }
}
