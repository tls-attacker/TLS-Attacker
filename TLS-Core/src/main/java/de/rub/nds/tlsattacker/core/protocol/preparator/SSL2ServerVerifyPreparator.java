package de.rub.nds.tlsattacker.core.protocol.preparator;

import de.rub.nds.tlsattacker.core.protocol.message.SSL2ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.SSL2ServerVerifyMessage;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;

public class SSL2ServerVerifyPreparator extends ProtocolMessagePreparator<SSL2ServerVerifyMessage> {

    private final SSL2ServerVerifyMessage message;

    public SSL2ServerVerifyPreparator(SSL2ServerVerifyMessage message, Chooser chooser) {
        super(chooser, message);
        this.message = message;
    }

    @Override
    protected void prepareProtocolMessageContents() {
        throw new UnsupportedOperationException("Not supported Yet");
    }
    
    public void prepareAfterParse() {
    }

}
