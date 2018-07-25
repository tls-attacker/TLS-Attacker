package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.protocol.message.GOSTClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.GOSTClientKeyExchangeParser;
import de.rub.nds.tlsattacker.core.protocol.parser.ProtocolMessageParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.GOSTClientKeyExchangePreparator;
import de.rub.nds.tlsattacker.core.protocol.preparator.ProtocolMessagePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.GOSTClientKeyExchangeSerializer;
import de.rub.nds.tlsattacker.core.protocol.serializer.ProtocolMessageSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;

public class GOSTClientKeyExchangeHandler extends ClientKeyExchangeHandler<GOSTClientKeyExchangeMessage> {

    public GOSTClientKeyExchangeHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public ProtocolMessageParser getParser(byte[] message, int pointer) {
        return new GOSTClientKeyExchangeParser(pointer, message, tlsContext.getChooser().getLastRecordVersion());
    }

    @Override
    public ProtocolMessagePreparator getPreparator(GOSTClientKeyExchangeMessage message) {
        return new GOSTClientKeyExchangePreparator(tlsContext.getChooser(), message);
    }

    @Override
    public ProtocolMessageSerializer getSerializer(GOSTClientKeyExchangeMessage message) {
        return new GOSTClientKeyExchangeSerializer(message, tlsContext.getChooser().getSelectedProtocolVersion());
    }

    @Override
    public void adjustTLSContext(GOSTClientKeyExchangeMessage message) {
        adjustPremasterSecret(message);
        adjustMasterSecret(message);
        setRecordCipher();
        spawnNewSession();
    }

}
