/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import de.rub.nds.tlsattacker.core.protocol.message.extension.UnknownExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.UnknownExtensionSerializer;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;

public class UnknownExtensionPreparator extends ExtensionPreparator<UnknownExtensionMessage> {

    private final UnknownExtensionMessage msg;

    public UnknownExtensionPreparator(Chooser chooser, UnknownExtensionMessage msg,
            UnknownExtensionSerializer serializer) {
        super(chooser, msg, serializer);
        this.msg = msg;
    }

    @Override
    public void prepareExtensionContent() {

        if (msg.getDataConfig() != null) {
            msg.setExtensionData(msg.getDataConfig());
        } else {
            msg.setExtensionData(new byte[] {});
        }
        if (msg.getTypeConfig() != null) {
            msg.setExtensionType(msg.getTypeConfig());
        } else {
            msg.setExtensionType(new byte[] {});
        }
        if (msg.getLengthConfig() != null) {
            msg.setExtensionLength(msg.getLengthConfig());
        } else {
            msg.setExtensionLength(msg.getExtensionData().getValue().length);
        }
    }

}
