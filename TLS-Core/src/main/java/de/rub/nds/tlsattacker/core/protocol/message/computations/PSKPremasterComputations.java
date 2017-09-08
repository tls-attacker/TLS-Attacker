/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.message.computations;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.util.ArrayConverter;;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;

/**
 *
 * @author 
 */
public class PSKPremasterComputations extends KeyExchangeComputations {

    @ModifiableVariableProperty(format = ModifiableVariableProperty.Format.PKCS1, type = ModifiableVariableProperty.Type.KEY_MATERIAL)
    private ModifiableByteArray PremasterSecret;
    
    private ModifiableByteArray psk;
    private ModifiableInteger psklength;
    
    public PSKPremasterComputations() {
    }

    public PSKPremasterComputations(ModifiableInteger psklength, ModifiableByteArray psk) {
        this.psklength = psklength;
        this.psk = psk;
    }
    
    @Override
    public ModifiableByteArray getPremasterSecret() {
        return PremasterSecret;
    }
    @Override
    public void setPremasterSecret(ModifiableByteArray PremasterSecret) {
        this.PremasterSecret = PremasterSecret;
    }
    @Override
    public void setPremasterSecret(byte[] value) {
        this.PremasterSecret = ModifiableVariableFactory.safelySetValue(this.PremasterSecret,
                value);
    }
    
    public void computePremasterSecrete(){
        byte[] length;
        length = ArrayConverter.intToBytes(psk.getValue().length, 2);
        byte[] nulls;
        nulls = ArrayConverter.intToBytes(0, psk.getValue().length);//Byte Output Stream zB In Serializer
        String test;
        test = length.toString();
        test.concat(nulls.toString());
        test.concat(length.toString());
        test.concat(psk.toString());
        this.premasterSecret = ModifiableVariableFactory.safelySetValue(premasterSecret, ArrayConverter.hexStringToByteArray(test));
    }
}
