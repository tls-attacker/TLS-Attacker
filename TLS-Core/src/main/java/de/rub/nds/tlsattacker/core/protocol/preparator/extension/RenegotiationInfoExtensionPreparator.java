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
import de.rub.nds.tlsattacker.core.protocol.message.extension.RenegotiationInfoExtensionMessage;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;

/**
 *
 * @author Matthias Terlinde <matthias.terlinde@rub.de>
 */
public class RenegotiationInfoExtensionPreparator extends ExtensionPreparator<RenegotiationInfoExtensionMessage> {

    private final RenegotiationInfoExtensionMessage message;

    /**
     * Constructor
     *
     * @param chooser
     * @param message
     */
    public RenegotiationInfoExtensionPreparator(Chooser chooser, RenegotiationInfoExtensionMessage message) {
        super(chooser, message);
        this.message = message;
    }

    @Override
    public void prepareExtensionContent() {
        message.setRenegotiationInfo(chooser.getConfig().getDefaultRenegotiationInfo());
        LOGGER.debug("Prepared the RenegotiationInfo extension with info "
                + ArrayConverter.bytesToHexString(chooser.getConfig().getDefaultRenegotiationInfo()));
    }

}
