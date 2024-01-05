/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import de.rub.nds.tlsattacker.core.protocol.message.extension.UnknownExtensionMessage;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;

public class UnknownExtensionPreparator extends ExtensionPreparator<UnknownExtensionMessage> {

    private final UnknownExtensionMessage msg;

    public UnknownExtensionPreparator(Chooser chooser, UnknownExtensionMessage msg) {
        super(chooser, msg);
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
