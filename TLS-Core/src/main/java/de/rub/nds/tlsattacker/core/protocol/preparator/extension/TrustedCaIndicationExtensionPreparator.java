/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import de.rub.nds.tlsattacker.core.protocol.message.extension.TrustedCaIndicationExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.trustedauthority.TrustedAuthority;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;

/**
 *
 * @author Matthias Terlinde <matthias.terlinde@rub.de>
 */
public class TrustedCaIndicationExtensionPreparator extends ExtensionPreparator<TrustedCaIndicationExtensionMessage> {

    private final TrustedCaIndicationExtensionMessage msg;

    public TrustedCaIndicationExtensionPreparator(TlsContext context, TrustedCaIndicationExtensionMessage message) {
        super(context, message);
        msg = message;
    }

    @Override
    public void prepareExtensionContent() {
        msg.setTrustedAuthorities(context.getConfig().getTrustedCaIndicationExtensionAuthorties());
        int taLength = 0;
        for (TrustedAuthority ta : msg.getTrustedAuthorities()) {
            taLength += ta.getLength();
        }
        msg.setTrustedAuthoritiesLength(taLength);
    }

}
