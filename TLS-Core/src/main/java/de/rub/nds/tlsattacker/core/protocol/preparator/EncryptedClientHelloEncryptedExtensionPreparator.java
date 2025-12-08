/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.preparator;

import de.rub.nds.tlsattacker.core.protocol.message.extension.EncryptedClientHelloEncryptedExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.ExtensionPreparator;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import java.util.List;

public class EncryptedClientHelloEncryptedExtensionPreparator
        extends ExtensionPreparator<EncryptedClientHelloEncryptedExtensionMessage> {

    private final EncryptedClientHelloEncryptedExtensionMessage msg;

    public EncryptedClientHelloEncryptedExtensionPreparator(
            Chooser chooser, EncryptedClientHelloEncryptedExtensionMessage message) {
        super(chooser, message);
        this.msg = message;
    }

    @Override
    public void prepareExtensionContent() {
        // include own ECH config in extension
        msg.setEchConfigs(List.of(chooser.getEchConfig()));
        int totalLength = 0;
        for (var config : msg.getEchConfigs()) {
            totalLength += config.getEchConfigBytes().length;
        }
        msg.setEchConfigsLength(totalLength);
    }
}
