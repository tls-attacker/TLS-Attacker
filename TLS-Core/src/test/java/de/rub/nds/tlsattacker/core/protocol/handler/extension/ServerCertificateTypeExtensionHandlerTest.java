/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import static org.junit.jupiter.api.Assertions.assertEquals;

import de.rub.nds.tlsattacker.core.constants.CertificateType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ServerCertificateTypeExtensionMessage;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.List;

public class ServerCertificateTypeExtensionHandlerTest extends
    AbstractExtensionMessageHandlerTest<ServerCertificateTypeExtensionMessage, ServerCertificateTypeExtensionHandler> {

    private final List<CertificateType> certList =
        Arrays.asList(CertificateType.OPEN_PGP, CertificateType.X509, CertificateType.RAW_PUBLIC_KEY);

    public ServerCertificateTypeExtensionHandlerTest() {
        super(ServerCertificateTypeExtensionMessage::new, ServerCertificateTypeExtensionHandler::new);
    }

    @Test
    @Override
    public void testAdjustTLSContext() {
        ServerCertificateTypeExtensionMessage msg = new ServerCertificateTypeExtensionMessage();
        msg.setCertificateTypes(CertificateType.toByteArray(certList));
        handler.adjustTLSContext(msg);
        assertEquals(certList, context.getServerCertificateTypeDesiredTypes());
    }
}
