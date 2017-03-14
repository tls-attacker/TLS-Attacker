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
import de.rub.nds.tlsattacker.modifiablevariable.biginteger.ModifiableBigInteger;
import de.rub.nds.tlsattacker.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.modifiablevariable.singlebyte.ModifiableByte;
import de.rub.nds.tlsattacker.tls.protocol.handler.ECDHClientKeyExchangeHandler;
import de.rub.nds.tlsattacker.tls.protocol.handler.ProtocolMessageHandler;
import de.rub.nds.tlsattacker.tls.protocol.message.computations.ECDHClientComputations;
import de.rub.nds.tlsattacker.tls.protocol.message.computations.KeyExchangeComputations;
import de.rub.nds.tlsattacker.tls.protocol.serializer.ECDHClientKeyExchangeSerializer;
import de.rub.nds.tlsattacker.tls.protocol.serializer.Serializer;
import de.rub.nds.tlsattacker.tls.workflow.TlsConfig;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import java.math.BigInteger;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class ECDHClientKeyExchangeMessage extends ClientKeyExchangeMessage {

    /**
     * EC public key x coordinate
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.PUBLIC_KEY)
    private ModifiableBigInteger publicKeyBaseX;
    /**
     * EC public key y coordinate
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.PUBLIC_KEY)
    private ModifiableBigInteger publicKeyBaseY;
    /**
     * EC point format of the encoded EC point
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    private ModifiableByte ecPointFormat;
    /**
     * Encoded EC point (without EC point format)
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.PUBLIC_KEY)
    private ModifiableByteArray ecPointEncoded;
    /**
     * Supported EC point formats (can be used to trigger compression)
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    private ModifiableByteArray supportedPointFormats;

    @HoldsModifiableVariable
    protected ECDHClientComputations computations;

    public ECDHClientKeyExchangeMessage() {
        super();
        computations = new ECDHClientComputations();
    }

    public ECDHClientKeyExchangeMessage(TlsConfig tlsConfig) {
        super(tlsConfig);
        computations = new ECDHClientComputations();
    }

    public ModifiableBigInteger getPublicKeyBaseX() {
        return publicKeyBaseX;
    }

    public void setPublicKeyBaseX(ModifiableBigInteger publicKeyBaseX) {
        this.publicKeyBaseX = publicKeyBaseX;
    }

    public void setPublicKeyBaseX(BigInteger ecPointBaseX) {
        this.publicKeyBaseX = ModifiableVariableFactory.safelySetValue(this.publicKeyBaseX, ecPointBaseX);
    }

    public ModifiableBigInteger getPublicKeyBaseY() {
        return publicKeyBaseY;
    }

    public void setPublicKeyBaseY(ModifiableBigInteger publicKeyBaseY) {
        this.publicKeyBaseY = publicKeyBaseY;
    }

    public void setPublicKeyBaseY(BigInteger ecPointBaseY) {
        this.publicKeyBaseY = ModifiableVariableFactory.safelySetValue(this.publicKeyBaseY, ecPointBaseY);
    }

    public ModifiableByte getEcPointFormat() {
        return ecPointFormat;
    }

    public void setEcPointFormat(ModifiableByte ecPointFormat) {
        this.ecPointFormat = ecPointFormat;
    }

    public void setEcPointFormat(Byte ecPointFormat) {
        this.ecPointFormat = ModifiableVariableFactory.safelySetValue(this.ecPointFormat, ecPointFormat);
    }

    public ModifiableByteArray getEcPointEncoded() {
        return ecPointEncoded;
    }

    public void setEcPointEncoded(ModifiableByteArray ecPointEncoded) {
        this.ecPointEncoded = ecPointEncoded;
    }

    public void setEcPointEncoded(byte[] ecPointEncoded) {
        this.ecPointEncoded = ModifiableVariableFactory.safelySetValue(this.ecPointEncoded, ecPointEncoded);
    }

    public ModifiableByteArray getSupportedPointFormats() {
        return supportedPointFormats;
    }

    public void setSupportedPointFormats(ModifiableByteArray supportedPointFormats) {
        this.supportedPointFormats = supportedPointFormats;
    }

    public void setSupportedPointFormats(byte[] supportedPointFormats) {
        this.supportedPointFormats = ModifiableVariableFactory.safelySetValue(this.supportedPointFormats,
                supportedPointFormats);
    }

    @Override
    public String toString() {
        String sb = super.toString();
        return sb;
    }

    @Override
    public KeyExchangeComputations getComputations() {
        return computations;
    }

    @Override
    public ProtocolMessageHandler getHandler(TlsContext context) {
        return new ECDHClientKeyExchangeHandler(context);
    }

    @Override
    public String toCompactString() {
        return "ECDH_CLIENT_KEY_EXCHANGE";
    }
}
