/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import de.rub.nds.tlsattacker.core.constants.AuthzDataFormat;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ServerAuthzExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.ServerAuthzExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.util.Arrays;
import java.util.List;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import org.junit.Test;

public class ServerAuthzExtensionPreparatorTest {

    private TlsContext context;
    private ServerAuthzExtensionMessage msg;
    private ServerAuthzExtensionPreparator preparator;
    private final List<AuthzDataFormat> authzFormatList = Arrays.asList(AuthzDataFormat.X509_ATTR_CERT,
            AuthzDataFormat.SAML_ASSERTION, AuthzDataFormat.X509_ATTR_CERT_URL, AuthzDataFormat.SAML_ASSERTION_URL);
    private final byte[] authzFormatListAsBytes = new byte[] { 0x00, 0x01, 0x02, 0x03 };
    private final int authzFormatListLength = 4;

    @Test
    public void testPreparator() {
        context = new TlsContext();
        context.getConfig().setServerAuthzExtensionDataFormat(authzFormatList);

        msg = new ServerAuthzExtensionMessage();
        preparator = new ServerAuthzExtensionPreparator(context.getChooser(), msg, new ServerAuthzExtensionSerializer(
                msg));

        preparator.prepare();

        assertArrayEquals(ExtensionType.SERVER_AUTHZ.getValue(), msg.getExtensionType().getValue());
        assertEquals(authzFormatListLength, (long) msg.getAuthzFormatListLength().getValue());
        assertArrayEquals(authzFormatListAsBytes, msg.getAuthzFormatList().getValue());
    }
}
