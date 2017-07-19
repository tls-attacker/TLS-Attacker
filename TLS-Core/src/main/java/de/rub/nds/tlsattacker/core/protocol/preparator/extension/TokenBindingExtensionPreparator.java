/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import de.rub.nds.tlsattacker.core.constants.TokenBindingKeyParameters;
import de.rub.nds.tlsattacker.core.protocol.message.extension.TokenBindingExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.TokenBindingExtensionSerializer;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;
import java.io.ByteArrayOutputStream;

/**
 *
 * @author Matthias Terlinde <matthias.terlinde@rub.de>
 */
public class TokenBindingExtensionPreparator extends ExtensionPreparator<TokenBindingExtensionMessage> {
    private final TokenBindingExtensionMessage message;

    public TokenBindingExtensionPreparator(TlsContext context, TokenBindingExtensionMessage message,
            TokenBindingExtensionSerializer serializer) {
        super(context, message, serializer);
        this.message = message;
    }

    @Override
    public void prepareExtensionContent() {
        message.setTokenbindingVersion(context.getConfig().getTokenBindingVersion().getByteValue());
        message.setParameterListLength(context.getConfig().getTokenBindingKeyParameters().length);
        ByteArrayOutputStream tokenbindingKeyParameters = new ByteArrayOutputStream();
        for (TokenBindingKeyParameters kp : context.getConfig().getTokenBindingKeyParameters()) {
            tokenbindingKeyParameters.write(kp.getKeyParameterValue());
        }
        message.setTokenbindingKeyParameters(tokenbindingKeyParameters.toByteArray());
    }

}
