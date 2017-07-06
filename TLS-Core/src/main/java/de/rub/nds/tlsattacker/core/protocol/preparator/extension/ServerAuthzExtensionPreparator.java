/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import de.rub.nds.tlsattacker.core.constants.AuthzDataFormat;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ServerAuthzExtensionMessage;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;

/**
 *
 * @author Matthias Terlinde <matthias.terlinde@rub.de>
 */
public class ServerAuthzExtensionPreparator extends ExtensionPreparator<ServerAuthzExtensionMessage> {

    private final ServerAuthzExtensionMessage msg;

    public ServerAuthzExtensionPreparator(TlsContext context, ServerAuthzExtensionMessage message) {
        super(context, message);
        msg = message;
    }

    @Override
    public void prepareExtensionContent() {
        msg.setAuthzFormatListLength(context.getConfig().getServerAuthzExtensionDataFormat().size());
        msg.setAuthzFormatList(AuthzDataFormat.listToByteArray(context.getConfig().getServerAuthzExtensionDataFormat()));
    }

}
