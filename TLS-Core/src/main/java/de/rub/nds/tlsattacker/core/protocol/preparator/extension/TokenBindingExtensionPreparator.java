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
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import java.io.ByteArrayOutputStream;

public class TokenBindingExtensionPreparator extends ExtensionPreparator<TokenBindingExtensionMessage> {

    private final TokenBindingExtensionMessage message;

    public TokenBindingExtensionPreparator(Chooser chooser, TokenBindingExtensionMessage message,
            TokenBindingExtensionSerializer serializer) {
        super(chooser, message, serializer);
        this.message = message;
    }

    @Override
    public void prepareExtensionContent() {

        message.setTokenbindingVersion(chooser.getConfig().getDefaultTokenBindingVersion().getByteValue());
        ByteArrayOutputStream tokenbindingKeyParameters = new ByteArrayOutputStream();
        for (TokenBindingKeyParameters kp : chooser.getConfig().getDefaultTokenBindingKeyParameters()) {
            tokenbindingKeyParameters.write(kp.getValue());
        }
        message.setTokenbindingKeyParameters(tokenbindingKeyParameters.toByteArray());
        message.setParameterListLength(message.getTokenbindingKeyParameters().getValue().length);
    }

}
