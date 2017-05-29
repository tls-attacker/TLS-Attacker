/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import de.rub.nds.tlsattacker.core.protocol.message.extension.TokenBindingExtensionMessage;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;

/**
 *
 * @author Matthias Terlinde <matthias.terlinde@rub.de>
 */
public class TokenBindingExtensionPreparator extends ExtensionPreparator<TokenBindingExtensionMessage> {
    private final TokenBindingExtensionMessage message;

    public TokenBindingExtensionPreparator(TlsContext context, TokenBindingExtensionMessage message) {
        super(context, message);
        this.message = message;
    }

    @Override
    public void prepareExtensionContent() {
        message.setMajor(context.getConfig().getTokenBindingMajor());
        message.setMinor(context.getConfig().getTokenBindingMinor());
        message.setTokenBindingKeyParameters(context.getConfig().getTokenBindingKeyParameters());
        LOGGER.debug("Prepared the TokenBindingExtensionMessage.");
    }

}
