/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PSKKeyExchangeModesExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.ExtensionSerializer;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;

/**
 * RFC draft-ietf-tls-tls13-21
 *
 * @author Marcel Maehren <marcel.maehren@rub.de>
 */
public class PSKKeyExchangeModesExtensionPreparator extends ExtensionPreparator<PSKKeyExchangeModesExtensionMessage> {

    private final PSKKeyExchangeModesExtensionMessage msg;
    public PSKKeyExchangeModesExtensionPreparator(Chooser chooser, PSKKeyExchangeModesExtensionMessage message,
            ExtensionSerializer<PSKKeyExchangeModesExtensionMessage> serializer) {
        super(chooser, message, serializer);
        this.msg = message;
    }

    @Override
    public void prepareExtensionContent() {
        LOGGER.debug("Preparing PSKKeyExchangeModesExtensionMessage");
        msg.setKeyExchangeModesListBytes(chooser.getConfig().getPSKKeyExchangeModes());
        msg.setKeyExchangeModesListLength(chooser.getConfig().getPSKKeyExchangeModes().length);
    }
}
