/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.tlsattacker.core.protocol.message.extension.HRRKeyShareExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.HRRKeyShareExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.HRRKeyShareExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.HRRKeyShareExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;

/**
 * This handler processes the KeyShare extensions in HelloRetryRequest message,
 * as defined in
 * https://tools.ietf.org/html/draft-ietf-tls-tls13-21#section-4.2.7
 */
public class HrrKeyShareExtensionHandler extends ExtensionHandler<HRRKeyShareExtensionMessage> {

    public HrrKeyShareExtensionHandler(TlsContext context) {
        super(context);
    }

    @Override
    public HRRKeyShareExtensionParser getParser(byte[] message, int pointer) {
        return new HRRKeyShareExtensionParser(pointer, message);
    }

    @Override
    public HRRKeyShareExtensionPreparator getPreparator(HRRKeyShareExtensionMessage message) {
        return new HRRKeyShareExtensionPreparator(context.getChooser(), message, getSerializer(message));
    }

    @Override
    public HRRKeyShareExtensionSerializer getSerializer(HRRKeyShareExtensionMessage message) {
        return new HRRKeyShareExtensionSerializer(message);
    }

    @Override
    public void adjustTLSExtensionContext(HRRKeyShareExtensionMessage message) {
    }

}
