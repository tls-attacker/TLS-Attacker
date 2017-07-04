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
import de.rub.nds.tlsattacker.core.protocol.message.extension.AlpnExtensionMessage;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;

/**
 *
 * @author Matthias Terlinde <matthias.terlinde@rub.de>
 */
public class AlpnExtensionPreparator extends ExtensionPreparator<AlpnExtensionMessage> {

    private final AlpnExtensionMessage msg;

    public AlpnExtensionPreparator(TlsContext context, AlpnExtensionMessage message) {
        super(context, message);
        this.msg = message;
    }

    @Override
    public void prepareExtensionContent() {
        msg.setAlpnAnnouncedProtocols(context.getConfig().getApplicationLayerProtocolNegotiationAnnouncedProtocols()
                .getBytes());
        LOGGER.debug("Prepared the ALPN Extension with announced protocols "
                + ArrayConverter.bytesToHexString(msg.getAlpnAnnouncedProtocols()));
        msg.setAlpnExtensionLength(msg.getAlpnAnnouncedProtocols().getValue().length);
        LOGGER.debug("Prepared the ALPN Extension with announced protocols length "
                + msg.getAlpnExtensionLength().getValue());
    }

}
