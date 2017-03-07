/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.message.computations;

import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.tlsattacker.modifiablevariable.biginteger.ModifiableBigInteger;
import de.rub.nds.tlsattacker.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.modifiablevariable.integer.ModifiableInteger;
import java.math.BigInteger;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class DHEServerComputations extends KeyExchangeComputations {

    /**
     * server's private key
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.PRIVATE_KEY)
    private ModifiableBigInteger privateKey;
    /**
     * Length of the serialized DH modulus
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger serializedPLength;
    /**
     * serialized DH modulus
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.PUBLIC_KEY)
    private ModifiableByteArray serializedP;
    /**
     * Length of the serialized DH generator
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger serializedGLength;
    /**
     * serialized DH generator
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.PUBLIC_KEY)
    private ModifiableByteArray serializedG;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.KEY_MATERIAL)
    private ModifiableByteArray serverRandom;

    public DHEServerComputations() {
    }

    public ModifiableBigInteger getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(ModifiableBigInteger privateKey) {
        this.privateKey = privateKey;
    }

    public void setPrivateKey(BigInteger privateKey) {
        this.privateKey = ModifiableVariableFactory.safelySetValue(this.privateKey, privateKey);
    }

    public ModifiableInteger getSerializedPLength() {
        return serializedPLength;
    }

    public void setSerializedPLength(ModifiableInteger serializedPLength) {
        this.serializedPLength = serializedPLength;
    }

    public void setSerializedPLength(Integer pLength) {
        this.serializedPLength = ModifiableVariableFactory.safelySetValue(this.serializedPLength, pLength);
    }

    public ModifiableByteArray getSerializedP() {
        return serializedP;
    }

    public void setSerializedP(ModifiableByteArray serializedP) {
        this.serializedP = serializedP;
    }

    public void setSerializedP(byte[] serializedP) {
        this.serializedP = ModifiableVariableFactory.safelySetValue(this.serializedP, serializedP);
    }

    public ModifiableInteger getSerializedGLength() {
        return serializedGLength;
    }

    public void setSerializedGLength(ModifiableInteger serializedGLength) {
        this.serializedGLength = serializedGLength;
    }

    public void setSerializedGLength(Integer gLength) {
        this.serializedGLength = ModifiableVariableFactory.safelySetValue(this.serializedGLength, gLength);
    }

    public ModifiableByteArray getSerializedG() {
        return serializedG;
    }

    public void setSerializedG(ModifiableByteArray serializedG) {
        this.serializedG = serializedG;
    }

    public void setSerializedG(byte[] serializedG) {
        this.serializedG = ModifiableVariableFactory.safelySetValue(this.serializedG, serializedG);
    }

    public ModifiableByteArray getServerRandom() {
        return serverRandom;
    }

    public void setServerRandom(ModifiableByteArray serverRandom) {
        this.serverRandom = serverRandom;
    }

    public void setServerRandom(byte[] serverRandom) {
        this.serverRandom = ModifiableVariableFactory.safelySetValue(this.serverRandom, serverRandom);
    }
}
