package de.rub.nds.tlsattacker.core.protocol.parser;

import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.crypto.keyexchange.TLSGostKeyTransportBlob;
import de.rub.nds.tlsattacker.core.protocol.message.GOSTClientKeyExchangeMessage;

public class GOSTClientKeyExchangeParser extends ClientKeyExchangeParser<GOSTClientKeyExchangeMessage> {

    public GOSTClientKeyExchangeParser(int startposition, byte[] array, ProtocolVersion version) {
        super(startposition, array, version);
    }

    @Override
    protected void parseHandshakeMessageContent(GOSTClientKeyExchangeMessage msg) {
        LOGGER.debug("Parsing GOSTClientKeyExchangeMessage");
        byte[] bytes = parseArrayOrTillEnd(Integer.MAX_VALUE);
        TLSGostKeyTransportBlob blob = TLSGostKeyTransportBlob.getInstance(bytes);
        msg.setKeyTransportBlob(blob);
    }

    @Override
    protected GOSTClientKeyExchangeMessage createHandshakeMessage() {
        return new GOSTClientKeyExchangeMessage();
    }

}
