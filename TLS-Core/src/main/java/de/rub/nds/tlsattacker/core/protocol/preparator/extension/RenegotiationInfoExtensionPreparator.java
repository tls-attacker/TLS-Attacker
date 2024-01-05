/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.protocol.message.extension.RenegotiationInfoExtensionMessage;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class RenegotiationInfoExtensionPreparator
        extends ExtensionPreparator<RenegotiationInfoExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final RenegotiationInfoExtensionMessage message;

    public RenegotiationInfoExtensionPreparator(
            Chooser chooser, RenegotiationInfoExtensionMessage message) {
        super(chooser, message);
        this.message = message;
    }

    @Override
    public void prepareExtensionContent() {
        if (chooser.getContext().getTlsContext().getLastClientVerifyData() != null
                && chooser.getContext().getTlsContext().getLastServerVerifyData() != null) {
            // We are renegotiating
            if (chooser.getContext().getTalkingConnectionEndType() == ConnectionEndType.CLIENT) {
                message.setRenegotiationInfo(
                        chooser.getContext().getTlsContext().getLastClientVerifyData());
            } else {
                message.setRenegotiationInfo(
                        ArrayConverter.concatenate(
                                chooser.getContext().getTlsContext().getLastClientVerifyData(),
                                chooser.getContext().getTlsContext().getLastServerVerifyData()));
            }
        } else {
            // First time we send this message
            if (chooser.getContext().getTalkingConnectionEndType() == ConnectionEndType.CLIENT) {
                message.setRenegotiationInfo(
                        chooser.getConfig().getDefaultClientRenegotiationInfo());
            } else {
                message.setRenegotiationInfo(
                        chooser.getConfig().getDefaultServerRenegotiationInfo());
            }
        }
        message.setRenegotiationInfoLength(message.getRenegotiationInfo().getValue().length);
        LOGGER.debug(
                "Prepared the RenegotiationInfo extension with info {}",
                message.getRenegotiationInfo().getValue());
    }
}
