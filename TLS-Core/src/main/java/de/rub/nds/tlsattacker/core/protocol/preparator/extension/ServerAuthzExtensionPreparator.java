/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import de.rub.nds.tlsattacker.core.constants.AuthzDataFormat;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ServerAuthzExtensionMessage;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;

public class ServerAuthzExtensionPreparator
        extends ExtensionPreparator<ServerAuthzExtensionMessage> {

    private final ServerAuthzExtensionMessage msg;

    public ServerAuthzExtensionPreparator(Chooser chooser, ServerAuthzExtensionMessage message) {
        super(chooser, message);
        msg = message;
    }

    @Override
    public void prepareExtensionContent() {
        msg.setAuthzFormatListLength(
                chooser.getConfig().getServerAuthzExtensionDataFormat().size());
        msg.setAuthzFormatList(
                AuthzDataFormat.listToByteArray(
                        chooser.getConfig().getServerAuthzExtensionDataFormat()));
    }
}
