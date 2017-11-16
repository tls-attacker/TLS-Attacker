/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.TokenBindingKeyParameters;
import de.rub.nds.tlsattacker.core.constants.TokenBindingVersion;
import de.rub.nds.tlsattacker.core.protocol.message.extension.TokenBindingExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.TokenBindingExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.util.LinkedList;
import java.util.List;
import static org.junit.Assert.assertArrayEquals;
import org.junit.Before;
import org.junit.Test;

public class TokenBindingExtensionPreparatorTest {

    private final TokenBindingVersion tokenbindingVersion = TokenBindingVersion.DRAFT_13;
    private List<TokenBindingKeyParameters> keyParameters;
    private final byte[] keyParameterAsByteArray = new byte[] { TokenBindingKeyParameters.ECDSAP256.getValue() };

    private TlsContext context;
    private TokenBindingExtensionMessage message;
    private TokenBindingExtensionPreparator preparator;

    @Before
    public void setUp() {
        context = new TlsContext();
        message = new TokenBindingExtensionMessage();
        preparator = new TokenBindingExtensionPreparator(context.getChooser(), message,
                new TokenBindingExtensionSerializer(message));
        keyParameters = new LinkedList<>();
        keyParameters.add(TokenBindingKeyParameters.ECDSAP256);
    }

    @Test
    public void testPreparator() {
        context.getConfig().setDefaultTokenBindingVersion(tokenbindingVersion);
        context.getConfig().setDefaultTokenBindingKeyParameters(keyParameters);

        preparator.prepare();

        assertArrayEquals(ExtensionType.TOKEN_BINDING.getValue(), message.getExtensionType().getValue());
        assertArrayEquals(tokenbindingVersion.getByteValue(), message.getTokenbindingVersion().getValue());
        assertArrayEquals(keyParameterAsByteArray, message.getTokenbindingKeyParameters().getValue());
    }

    @Test
    public void testNoContextPrepare() {
        preparator.prepare();
    }

}
