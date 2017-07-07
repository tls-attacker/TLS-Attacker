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
import de.rub.nds.tlsattacker.core.workflow.TlsContext;

/**
 * This handler processes the KeyShare extensions in HelloRetryRequest message,
 * as defined in
 * https://tools.ietf.org/html/draft-ietf-tls-tls13-21#section-4.2.7
 * 
 * @author Nurullah Erinola <nurullah.erinola@rub.de>
 */
public class HRRKeyShareExtensionHandler extends ExtensionHandler<HRRKeyShareExtensionMessage> {

    public HRRKeyShareExtensionHandler(TlsContext context) {
        super(context);
    }

    @Override
    public HRRKeyShareExtensionParser getParser(byte[] message, int pointer) {
        return new HRRKeyShareExtensionParser(pointer, message);
    }

    @Override
    public HRRKeyShareExtensionPreparator getPreparator(HRRKeyShareExtensionMessage message) {
        return new HRRKeyShareExtensionPreparator(context, message);
    }

    @Override
    public HRRKeyShareExtensionSerializer getSerializer(HRRKeyShareExtensionMessage message) {
        return new HRRKeyShareExtensionSerializer(message);
    }

    @Override
    public void adjustTLSContext(HRRKeyShareExtensionMessage message) {
        // Nothing to adjust
    }

}
