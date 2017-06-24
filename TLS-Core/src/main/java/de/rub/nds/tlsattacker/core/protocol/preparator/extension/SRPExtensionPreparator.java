/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SRPExtensionMessage;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;

/**
 *
 * @author Matthias Terlinde <matthias.terlinde@rub.de>
 */
public class SRPExtensionPreparator extends ExtensionPreparator<SRPExtensionMessage> {

    private final SRPExtensionMessage message;

    public SRPExtensionPreparator(TlsContext context, SRPExtensionMessage message) {
        super(context, message);
        this.message = message;
    }

    @Override
    public void prepareExtensionContent() {
        message.setSrpIdentifier(context.getConfig().getSecureRemotePasswordExtensionIdentifier());
        LOGGER.debug("Prepared the SRP Extension with user identifier "
                + ArrayConverter.bytesToHexString(message.getSrpIdentifier().getValue()));
        message.setSrpIdentifierLength(message.getSrpIdentifier().getValue().length);
        LOGGER.debug("Prepared the SRP Extension with user identifier length "
                + message.getSrpIdentifierLength().getValue());
    }

}
