/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.handler.extension;

import de.rub.nds.tlsattacker.tls.constants.NamedCurve;
import de.rub.nds.tlsattacker.tls.protocol.message.extension.KS.KSEntry;
import de.rub.nds.tlsattacker.tls.protocol.message.extension.KS.KeySharePair;
import de.rub.nds.tlsattacker.tls.protocol.message.extension.KeyShareExtensionMessage;
import de.rub.nds.tlsattacker.tls.protocol.parser.extension.ExtensionParser;
import de.rub.nds.tlsattacker.tls.protocol.parser.extension.KeyShareExtensionParser;
import de.rub.nds.tlsattacker.tls.protocol.preparator.extension.KeyShareExtensionPreparator;
import de.rub.nds.tlsattacker.tls.protocol.serializer.extension.KeyShareExtensionSerializer;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import java.util.LinkedList;
import java.util.List;

/**
 * @author Nurullah Erinola
 */
public class KeyShareExtensionHandler extends ExtensionHandler<KeyShareExtensionMessage> {

    public KeyShareExtensionHandler(TlsContext context) {
        super(context);
    }

    @Override
    public KeyShareExtensionParser getParser(byte[] message, int pointer) {
        return new KeyShareExtensionParser(pointer, message);
    }
    
    @Override
    public KeyShareExtensionPreparator getPreparator(KeyShareExtensionMessage message) {
        return new KeyShareExtensionPreparator(context, message);
    }

    @Override
    public KeyShareExtensionSerializer getSerializer(KeyShareExtensionMessage message) {
        return new KeyShareExtensionSerializer(message);
    }

    @Override
    public void adjustTLSContext(KeyShareExtensionMessage message) {
        List<KSEntry> ksEntryList = new LinkedList<>();
        for (KeySharePair pair: message.getKeyShareList()) {
            NamedCurve type = NamedCurve.getNamedCurve(pair.getKeyShareType().getValue());
            if (type != null) {
                ksEntryList.add(new KSEntry(type, pair.getKeyShare().getValue()));
            } else {
                LOGGER.warn("Unknown KS Type:" + ArrayConverter.bytesToHexString(pair.getKeyShareType().getValue()));
            }
        }
        context.setClientKSEntryList(ksEntryList);
    }
    
}
