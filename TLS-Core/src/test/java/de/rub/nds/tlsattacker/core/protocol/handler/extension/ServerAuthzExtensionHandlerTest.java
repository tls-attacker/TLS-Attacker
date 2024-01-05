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

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.AuthzDataFormat;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ServerAuthzExtensionMessage;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;

public class ServerAuthzExtensionHandlerTest
        extends AbstractExtensionMessageHandlerTest<
                ServerAuthzExtensionMessage, ServerAuthzExtensionHandler> {

    private final byte[] authzFormatListAsBytes = ArrayConverter.hexStringToByteArray("00010203");
    private final List<AuthzDataFormat> authzFormatList =
            Arrays.asList(
                    AuthzDataFormat.X509_ATTR_CERT,
                    AuthzDataFormat.SAML_ASSERTION,
                    AuthzDataFormat.X509_ATTR_CERT_URL,
                    AuthzDataFormat.SAML_ASSERTION_URL);

    public ServerAuthzExtensionHandlerTest() {
        super(ServerAuthzExtensionMessage::new, ServerAuthzExtensionHandler::new);
    }

    @Test
    @Override
    public void testadjustTLSExtensionContext() {
        ServerAuthzExtensionMessage msg = new ServerAuthzExtensionMessage();
        msg.setAuthzFormatList(authzFormatListAsBytes);
        handler.adjustTLSExtensionContext(msg);
        assertEquals(authzFormatList, context.getServerAuthzDataFormatList());
    }
}
