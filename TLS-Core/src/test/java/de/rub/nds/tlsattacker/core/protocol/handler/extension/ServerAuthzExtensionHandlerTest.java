/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.AuthzDataFormat;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ServerAuthzExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.ServerAuthzExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.ServerAuthzExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.ServerAuthzExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.util.Arrays;
import java.util.List;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.Test;

public class ServerAuthzExtensionHandlerTest {

    private final byte[] authzFormatListAsBytes = ArrayConverter.hexStringToByteArray("00010203");
    private final List<AuthzDataFormat> authzFormatList = Arrays.asList(AuthzDataFormat.X509_ATTR_CERT,
            AuthzDataFormat.SAML_ASSERTION, AuthzDataFormat.X509_ATTR_CERT_URL, AuthzDataFormat.SAML_ASSERTION_URL);
    private ServerAuthzExtensionHandler handler;
    private TlsContext context;

    @Before
    public void setUp() {
        context = new TlsContext();
        handler = new ServerAuthzExtensionHandler(context);
    }

    @Test
    public void testAdjustTLSContext() {
        ServerAuthzExtensionMessage msg = new ServerAuthzExtensionMessage();
        msg.setAuthzFormatList(authzFormatListAsBytes);

        handler.adjustTLSContext(msg);

        assertThat(authzFormatList, is(context.getServerAuthzDataFormatList()));
    }

    @Test
    public void testGetParser() {
        assertTrue(handler.getParser(new byte[0], 0) instanceof ServerAuthzExtensionParser);
    }

    @Test
    public void testGetPreparator() {
        assertTrue(handler.getPreparator(new ServerAuthzExtensionMessage()) instanceof ServerAuthzExtensionPreparator);
    }

    @Test
    public void testGetSerializer() {
        assertTrue(handler.getSerializer(new ServerAuthzExtensionMessage()) instanceof ServerAuthzExtensionSerializer);
    }
}
