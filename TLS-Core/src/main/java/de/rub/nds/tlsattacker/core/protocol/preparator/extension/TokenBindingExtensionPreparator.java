/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import de.rub.nds.tlsattacker.core.constants.TokenBindingKeyParameters;
import de.rub.nds.tlsattacker.core.protocol.message.extension.TokenBindingExtensionMessage;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import java.io.ByteArrayOutputStream;

public class TokenBindingExtensionPreparator
        extends ExtensionPreparator<TokenBindingExtensionMessage> {

    private final TokenBindingExtensionMessage message;

    public TokenBindingExtensionPreparator(Chooser chooser, TokenBindingExtensionMessage message) {
        super(chooser, message);
        this.message = message;
    }

    @Override
    public void prepareExtensionContent() {

        message.setTokenBindingVersion(
                chooser.getConfig().getDefaultTokenBindingVersion().getByteValue());
        ByteArrayOutputStream tokenbindingKeyParameters = new ByteArrayOutputStream();
        for (TokenBindingKeyParameters kp :
                chooser.getConfig().getDefaultTokenBindingKeyParameters()) {
            tokenbindingKeyParameters.write(kp.getValue());
        }
        message.setTokenBindingKeyParameters(tokenbindingKeyParameters.toByteArray());
        message.setParameterListLength(message.getTokenBindingKeyParameters().getValue().length);
    }
}
