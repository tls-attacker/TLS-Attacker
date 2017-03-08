/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.message;

import de.rub.nds.tlsattacker.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.tlsattacker.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.tlsattacker.tls.protocol.handler.ProtocolMessageHandler;
import de.rub.nds.tlsattacker.tls.protocol.handler.RSAClientKeyExchangeHandler;
import de.rub.nds.tlsattacker.tls.protocol.message.computations.DHClientComputations;
import de.rub.nds.tlsattacker.tls.protocol.message.computations.KeyExchangeComputations;
import de.rub.nds.tlsattacker.tls.protocol.message.computations.RSAClientComputations;
import de.rub.nds.tlsattacker.tls.protocol.serializer.RSAClientKeyExchangeSerializer;
import de.rub.nds.tlsattacker.tls.protocol.serializer.Serializer;
import de.rub.nds.tlsattacker.tls.workflow.TlsConfig;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class RSAClientKeyExchangeMessage extends ClientKeyExchangeMessage {

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger encryptedPremasterSecretLength;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.CIPHERTEXT)
    private ModifiableByteArray encryptedPremasterSecret;

    @HoldsModifiableVariable
    protected RSAClientComputations computations;

    public RSAClientKeyExchangeMessage(TlsConfig tlsConfig) {
        super(tlsConfig);
        computations = new RSAClientComputations();
    }

    public RSAClientKeyExchangeMessage() {
        super();
        computations = new RSAClientComputations();
    }

    public ModifiableInteger getEncryptedPremasterSecretLength() {
        return encryptedPremasterSecretLength;
    }

    public void setEncryptedPremasterSecretLength(ModifiableInteger encryptedPremasterSecretLength) {
        this.encryptedPremasterSecretLength = encryptedPremasterSecretLength;
    }

    public void setEncryptedPremasterSecretLength(int length) {
        this.encryptedPremasterSecretLength = ModifiableVariableFactory.safelySetValue(
                this.encryptedPremasterSecretLength, length);
    }

    public ModifiableByteArray getEncryptedPremasterSecret() {
        return encryptedPremasterSecret;
    }

    public void setEncryptedPremasterSecret(ModifiableByteArray encryptedPremasterSecret) {
        this.encryptedPremasterSecret = encryptedPremasterSecret;
    }

    public void setEncryptedPremasterSecret(byte[] value) {
        this.encryptedPremasterSecret = ModifiableVariableFactory.safelySetValue(this.encryptedPremasterSecret, value);
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("\nClient Key Exchange message:");
        return sb.toString();
    }

    @Override
    public RSAClientComputations getComputations() {
        return computations;
    }

    @Override
    public Serializer getSerializer() {
        return new RSAClientKeyExchangeSerializer(this);
    }
}
