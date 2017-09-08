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
//import de.rub.nds.tlsattacker.core.protocol.message.computations.PSKIdentity;
import de.rub.nds.tlsattacker.core.protocol.message.computations.PSKPremasterComputations;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.util.List;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
/**
 *
 * @author florian
 */
@XmlRootElement
public class PSKClientKeyExchangeMessage extends ClientKeyExchangeMessage {

    @HoldsModifiableVariable
    @XmlElement
    protected PSKPremasterComputations premastersecret;
    @ModifiableVariableProperty(format = ModifiableVariableProperty.Format.PKCS1, type = ModifiableVariableProperty.Type.PSK_IDENTITY)
    private ModifiableByteArray identity;
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger identity_length;
    
    public PSKClientKeyExchangeMessage(Config tlsConfig) {
        super(tlsConfig);
    }

    public PSKClientKeyExchangeMessage() {
        super();
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        if(identity_length!=null){
            sb.append("\nPSKIdentity Length:");
            sb.append(identity_length.getValue());
            }
        if(identity!=null){
            sb.append("\nPSKIdentity:");
            sb.append(ArrayConverter.bytesToHexString(identity.getValue()));
        }
        return sb.toString();
    }

    @Override
    public PSKPremasterComputations getComputations() {
        return premastersecret;
    }
    public ModifiableByteArray getIdentity() {
        return identity;
    }
    
    public void setIdentity(ModifiableByteArray identity){
        this.identity=identity;
    }
    
    public void setIdentity(byte[] identity){
        this.identity = ModifiableVariableFactory.safelySetValue(this.identity, identity);
    }
    
    public ModifiableInteger getIdentityLength() {
        return identity_length;
    }
    
    public void setIdentityLength(ModifiableInteger identity_length){
        this.identity_length=identity_length;
    }
    
    public void setIdentityLength(int identity_length){
        this.identity_length=ModifiableVariableFactory.safelySetValue(this.identity_length, identity_length);
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
         if (premastersecret == null) {
            premastersecret = new PSKPremasterComputations();
        }
        }

    @Override
    public List<ModifiableVariableHolder> getAllModifiableVariableHolders() {
        List<ModifiableVariableHolder> holders = super.getAllModifiableVariableHolders();
        if (premastersecret != null) {
            holders.add(premastersecret);
        }
        return holders;
    }

}

