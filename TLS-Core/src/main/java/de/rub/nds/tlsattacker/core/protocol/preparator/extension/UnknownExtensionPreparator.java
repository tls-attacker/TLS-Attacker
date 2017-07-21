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

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class UnknownExtensionPreparator extends ExtensionPreparator<UnknownExtensionMessage> {

    private final UnknownExtensionMessage msg;

    public UnknownExtensionPreparator(Chooser chooser, UnknownExtensionMessage msg,
            UnknownExtensionSerializer serializer) {
        super(chooser, msg, serializer);
        this.msg = msg;
    }

    @Override
    public void prepareExtensionContent() {
        msg.setExtensionData(msg.getDataConfig());
        msg.setExtensionType(msg.getTypeConfig());
        msg.setExtensionLength(msg.getLengthConfig());
    }

}
