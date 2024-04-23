package de.rub.nds.tlsattacker.core.stun.preparator;

import javax.security.sasl.Sasl;

import de.rub.nds.protocol.constants.MacAlgorithm;
import de.rub.nds.protocol.crypto.mac.MacCalculator;
import de.rub.nds.tlsattacker.core.stun.model.MessageIntegrityAttribute;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;

public class MessageIntegrityPreparator extends StunAttributePreparator<MessageIntegrityAttribute> {

    public MessageIntegrityPreparator(Chooser chooser, MessageIntegrityAttribute attribute) {
        super(chooser, attribute);
    }

    @Override
    public void prepareContent() {
        getObject().setHmac(computeHmac());
    }

    @Override
    public void prepareAfterParse() {
        //TODO validate HMAC's
    }

    public byte[] computeHmac() {
        byte[] password = chooser.getConfig().getIceConfig().getDefaultStunPassword();
        String username = chooser.getContext().getIceContext().getStunUsername();
        String realm = chooser.getContext().getIceContext().getRealm();
        byte[] key;
        if (realm == null) {
            //Use short term credentials
            key = saslPrep(new String(password));
        } else {
            //Use long term credentials
            key = saslPrep(username + ":" + realm + ":" + new String(password)); 
        }
        //Initialize HMAC SHA1
        return MacCalculator.compute(key, chooser.getIceChooser().getContext().getMessageTranscript(), MacAlgorithm.HMAC_SHA1);
        
    }

    public byte[] saslPrep(String input) {
        return input.getBytes(); //TODO I dont have the light in me to implement this - hope its fine anyways
    }
}
