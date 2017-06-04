/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator;

import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.HelloRetryRequestMessage;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;
import de.rub.nds.modifiablevariable.util.ArrayConverter;

/**
 *
 * @author Nurullah Erinola
 */
public class HelloRetryRequestPreparator extends HandshakeMessagePreparator<HelloRetryRequestMessage> {

    private final HelloRetryRequestMessage msg;

    public HelloRetryRequestPreparator(TlsContext context, HelloRetryRequestMessage message) {
        super(context, message);
        this.msg = message;
    }

    @Override
    public void prepareHandshakeMessageContents() {
        prepareProtocolVersion();
        prepareExtensionLength();
        prepareExtensions();
    }

    private void prepareProtocolVersion() {
        ProtocolVersion ourVersion = context.getConfig().getHighestProtocolVersion();
        if (context.getConfig().isEnforceSettings()) {
            msg.setProtocolVersion(ourVersion.getValue());
        } else {
            msg.setProtocolVersion(ProtocolVersion.TLS13.getValue());
        }
        LOGGER.debug("ProtocolVersion: " + ArrayConverter.bytesToHexString(msg.getProtocolVersion().getValue()));
    }

}
