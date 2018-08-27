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
import de.rub.nds.tlsattacker.core.protocol.message.extension.HRRKeyShareExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.HRRKeyShareExtensionSerializer;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class HRRKeyShareExtensionPreparator extends ExtensionPreparator<HRRKeyShareExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final HRRKeyShareExtensionMessage msg;

    public HRRKeyShareExtensionPreparator(Chooser chooser, HRRKeyShareExtensionMessage message,
            HRRKeyShareExtensionSerializer serializer) {
        super(chooser, message, serializer);
        this.msg = message;
    }

    @Override
    public void prepareExtensionContent() {
        LOGGER.debug("Preparing HRRKeyShareExtensionMessage");
        prepareSelectedGroup(msg);
    }

    private void prepareSelectedGroup(HRRKeyShareExtensionMessage msg) {
        msg.setSelectedGroup(chooser.getConfig().getDefaultSelectedNamedGroup().getValue());
        LOGGER.debug("SelectedGroup: " + ArrayConverter.bytesToHexString(msg.getSelectedGroup().getValue()));
    }

}
