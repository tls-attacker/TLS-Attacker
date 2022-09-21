/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import de.rub.nds.tlsattacker.core.constants.AuthzDataFormat;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ServerAuthzExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.ServerAuthzExtensionSerializer;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.List;

public class ServerAuthzExtensionPreparatorTest extends AbstractExtensionMessagePreparatorTest<
    ServerAuthzExtensionMessage, ServerAuthzExtensionSerializer, ServerAuthzExtensionPreparator> {

    private final List<AuthzDataFormat> authzFormatList = Arrays.asList(AuthzDataFormat.X509_ATTR_CERT,
        AuthzDataFormat.SAML_ASSERTION, AuthzDataFormat.X509_ATTR_CERT_URL, AuthzDataFormat.SAML_ASSERTION_URL);
    private final byte[] authzFormatListAsBytes = new byte[] { 0x00, 0x01, 0x02, 0x03 };
    private final int authzFormatListLength = 4;

    public ServerAuthzExtensionPreparatorTest() {
        super(ServerAuthzExtensionMessage::new, ServerAuthzExtensionMessage::new, ServerAuthzExtensionSerializer::new,
            ServerAuthzExtensionPreparator::new);
    }

    @Test
    @Override
    public void testPrepare() {
        context.getConfig().setServerAuthzExtensionDataFormat(authzFormatList);

        preparator.prepare();

        assertArrayEquals(ExtensionType.SERVER_AUTHZ.getValue(), message.getExtensionType().getValue());
        assertEquals(4, message.getAuthzFormatListLength().getValue());
        assertArrayEquals(authzFormatListAsBytes, message.getAuthzFormatList().getValue());
    }
}
