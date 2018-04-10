/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.tlsattacker.core.constants.PskKeyExchangeMode;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PSKKeyExchangeModesExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.ExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.PSKKeyExchangeModesExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.ExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.PSKKeyExchangeModesExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.ExtensionSerializer;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.PSKKeyExchangeModesExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.util.LinkedList;

/**
 * RFC draft-ietf-tls-tls13-21
 */
public class PSKKeyExchangeModesExtensionHandler extends ExtensionHandler<PSKKeyExchangeModesExtensionMessage> {

    public PSKKeyExchangeModesExtensionHandler(TlsContext context) {
        super(context);
    }

    @Override
    public ExtensionParser getParser(byte[] message, int pointer) {
        return new PSKKeyExchangeModesExtensionParser(pointer, message);
    }

    @Override
    public ExtensionPreparator getPreparator(PSKKeyExchangeModesExtensionMessage message) {
        return new PSKKeyExchangeModesExtensionPreparator(context.getChooser(), message, getSerializer(message));
    }

    @Override
    public ExtensionSerializer getSerializer(PSKKeyExchangeModesExtensionMessage message) {
        return new PSKKeyExchangeModesExtensionSerializer(message);
    }

    @Override
    public void adjustTLSExtensionContext(PSKKeyExchangeModesExtensionMessage message) {
        if (message.getKeyExchangeModesListBytes() != null) {
            adjustKeyExchangeModes(message);
        }
    }

    private void adjustKeyExchangeModes(PSKKeyExchangeModesExtensionMessage message) {
        context.setClientPskKeyExchangeModes(new LinkedList<PskKeyExchangeMode>());
        for (byte exchangeModeByte : message.getKeyExchangeModesListBytes().getValue()) {
            PskKeyExchangeMode mode = PskKeyExchangeMode.getExchangeMode(exchangeModeByte);
            context.getClientPskKeyExchangeModes().add(mode);
        }
    }

}
