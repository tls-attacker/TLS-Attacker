/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.protocol.message.extension.CachedInfoExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.cachedinfo.CachedObject;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.ExtensionSerializer;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;

/**
 *
 * @author Matthias Terlinde <matthias.terlinde@rub.de>
 */
public class CachedInfoExtensionPreparator extends ExtensionPreparator<CachedInfoExtensionMessage> {

    private final CachedInfoExtensionMessage msg;

    public CachedInfoExtensionPreparator(Chooser chooser, CachedInfoExtensionMessage message,
            ExtensionSerializer<CachedInfoExtensionMessage> serializer) {
        super(chooser, message, serializer);
        msg = message;
    }

    @Override
    public void prepareExtensionContent() {
        msg.setCachedInfo(chooser.getConfig().getCachedObjectList());
        msg.setIsClientState(chooser.getConfig().isCachedInfoExtensionIsClientState());
        int payloadLength = 0;
        for (CachedObject co : msg.getCachedInfo()) {
            payloadLength += 1;
            if (msg.getIsClientState().getValue()) {
                payloadLength += ExtensionByteLength.CACHED_INFO_HASH_LENGTH;
                payloadLength += co.getHashValue().getValue().length;
            }
        }
        msg.setCachedInfoLength(payloadLength);
    }

}
