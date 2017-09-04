/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.message;

import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.protocol.ModifiableVariableHolder;
import de.rub.nds.tlsattacker.core.protocol.handler.ProtocolMessageHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.PSKClientKeyExchangeHandler;
import de.rub.nds.tlsattacker.core.protocol.message.computations.PSKIdentity;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.util.List;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import java.math.BigInteger;
/**
 *
 * @author florian
 */
@XmlRootElement
public class PSKClientKeyExchangeMessage extends ClientKeyExchangeMessage {

    @HoldsModifiableVariable
    @XmlElement
    protected PSKIdentity pskidentity;
    
    public PSKClientKeyExchangeMessage(Config tlsConfig) {
        super(tlsConfig);
    }

    public PSKClientKeyExchangeMessage() {
        super();
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("\nClient Key Exchange message:");
        return sb.toString();
    }

    @Override
    public PSKIdentity getComputations() {
        return pskidentity;
    }
    public PSKIdentity getPSKIdentity(){
        return pskidentity;
    }

    @Override
    public ProtocolMessageHandler getHandler(TlsContext context) {
        return new PSKClientKeyExchangeHandler(context);
    }

    @Override
    public String toCompactString() {
        return "PSK_CLIENT_KEY_EXCHANGE";
    }

    @Override
    public void prepareComputations() {
        if (pskidentity == null) {
            pskidentity = new PSKIdentity();
        }
    }

    @Override
    public List<ModifiableVariableHolder> getAllModifiableVariableHolders() {
        List<ModifiableVariableHolder> holders = super.getAllModifiableVariableHolders();
        if (pskidentity != null) {
            holders.add(pskidentity);
        }
        return holders;
    }

}

