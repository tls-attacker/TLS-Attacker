/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import de.rub.nds.protocol.util.SilentByteArrayOutputStream;
import de.rub.nds.tlsattacker.core.protocol.message.extension.CachedInfoExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.cachedinfo.CachedObject;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.CachedObjectSerializer;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;

public class CachedInfoExtensionPreparator extends ExtensionPreparator<CachedInfoExtensionMessage> {

    private final CachedInfoExtensionMessage msg;

    public CachedInfoExtensionPreparator(Chooser chooser, CachedInfoExtensionMessage message) {
        super(chooser, message);
        msg = message;
    }

    @Override
    public void prepareExtensionContent() {
        SilentByteArrayOutputStream stream = new SilentByteArrayOutputStream();
        for (CachedObject co : msg.getCachedInfo()) {
            CachedObjectPreparator preparator = new CachedObjectPreparator(chooser, co);
            preparator.prepare();
            CachedObjectSerializer serializer = new CachedObjectSerializer(co);
            stream.write(serializer.serialize());
        }
        msg.setCachedInfoBytes(stream.toByteArray());
        msg.setCachedInfoLength(msg.getCachedInfoBytes().getValue().length);
    }
}
