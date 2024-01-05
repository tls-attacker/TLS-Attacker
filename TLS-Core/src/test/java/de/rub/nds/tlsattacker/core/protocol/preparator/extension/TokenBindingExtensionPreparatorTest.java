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

import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.TokenBindingKeyParameters;
import de.rub.nds.tlsattacker.core.constants.TokenBindingVersion;
import de.rub.nds.tlsattacker.core.protocol.message.extension.TokenBindingExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.TokenBindingExtensionSerializer;
import java.util.List;
import org.junit.jupiter.api.Test;

public class TokenBindingExtensionPreparatorTest
        extends AbstractExtensionMessagePreparatorTest<
                TokenBindingExtensionMessage,
                TokenBindingExtensionSerializer,
                TokenBindingExtensionPreparator> {

    public TokenBindingExtensionPreparatorTest() {
        super(
                TokenBindingExtensionMessage::new,
                TokenBindingExtensionSerializer::new,
                TokenBindingExtensionPreparator::new);
    }

    @Test
    public void testPrepare() {
        context.getConfig().setDefaultTokenBindingVersion(TokenBindingVersion.DRAFT_13);
        context.getConfig()
                .setDefaultTokenBindingKeyParameters(List.of(TokenBindingKeyParameters.ECDSAP256));

        preparator.prepare();

        assertArrayEquals(
                ExtensionType.TOKEN_BINDING.getValue(), message.getExtensionType().getValue());
        assertArrayEquals(
                TokenBindingVersion.DRAFT_13.getByteValue(),
                message.getTokenBindingVersion().getValue());
        assertArrayEquals(
                new byte[] {TokenBindingKeyParameters.ECDSAP256.getValue()},
                message.getTokenBindingKeyParameters().getValue());
    }
}
