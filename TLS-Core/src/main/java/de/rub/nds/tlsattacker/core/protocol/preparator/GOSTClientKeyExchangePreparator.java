package de.rub.nds.tlsattacker.core.protocol.preparator;

import de.rub.nds.tlsattacker.core.protocol.message.ClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.GOSTClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;

public class GOSTClientKeyExchangePreparator extends ClientKeyExchangePreparator<GOSTClientKeyExchangeMessage> {

    public GOSTClientKeyExchangePreparator(Chooser chooser, ClientKeyExchangeMessage message) {
        super(chooser, message);
    }

    @Override
    protected void prepareHandshakeMessageContents() {

    }

}
