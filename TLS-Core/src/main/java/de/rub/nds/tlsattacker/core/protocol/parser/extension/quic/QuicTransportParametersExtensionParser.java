/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.parser.extension.quic;

import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.extension.quic.QuicTransportParameterEntry;
import de.rub.nds.tlsattacker.core.protocol.message.extension.quic.QuicTransportParameters;
import de.rub.nds.tlsattacker.core.protocol.message.extension.quic.QuicTransportParametersExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.quic.constants.QuicTransportParameterEntryTypes;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.ExtensionParser;
import java.io.InputStream;

public class QuicTransportParametersExtensionParser
        extends ExtensionParser<QuicTransportParametersExtensionMessage> {

    public QuicTransportParametersExtensionParser(InputStream stream, TlsContext tlsContext) {
        super(stream, tlsContext);
    }

    @Override
    public void parse(QuicTransportParametersExtensionMessage msg) {
        while (getBytesLeft() > 0) {
            QuicTransportParameterEntry entry = new QuicTransportParameterEntry();
            QuicTransportParameterEntryTypes types =
                    QuicTransportParameterEntryTypes.getParameterEntryType(parseByteField(1));

            if (types == QuicTransportParameterEntryTypes.GOOGLE
                    || types == QuicTransportParameterEntryTypes.PROVISIONAL_PARAMETERS) {
                parseByteField(1);
            } else if (types == QuicTransportParameterEntryTypes.UNKNOWN) {
                // upon finding unknown type, parse all bytes
                parseTillEnd();
                break;
            }
            byte length = parseByteField(1);
            byte[] value = parseByteArrayField(length);
            entry.setEntryType(types);
            entry.setEntryLength(length);
            entry.setEntryValue(value);
            msg.getTransportParameterEntries().add(entry);
        }
        msg.setQuicTransportParameters(
                new QuicTransportParameters(msg.getTransportParameterEntries()));
    }
}
