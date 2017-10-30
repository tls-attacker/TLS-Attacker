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
import de.rub.nds.tlsattacker.core.protocol.handler.PSKECDHClientKeyExchangeHandler;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.util.List;
import javax.xml.bind.annotation.XmlRootElement;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.biginteger.ModifiableBigInteger;
import de.rub.nds.modifiablevariable.singlebyte.ModifiableByte;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.protocol.message.computations.ECDHClientComputations;
import java.math.BigInteger;

/**
 *
 * @author Florian Linsner - florian.linsner@rub.de
 */
@XmlRootElement
public class PSKECDHClientKeyExchangeMessage extends ClientKeyExchangeMessage {

    @ModifiableVariableProperty(format = ModifiableVariableProperty.Format.PKCS1, type = ModifiableVariableProperty.Type.PUBLIC_KEY)
    private ModifiableByteArray identity;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableByteArray identityLength;
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

    public PSKECDHClientKeyExchangeMessage(Config tlsConfig) {
        super(tlsConfig);
    }

    public PSKECDHClientKeyExchangeMessage() {
        super();
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        if (identityLength != null) {
            sb.append("\nPSKIdentity Length:");
            sb.append(identityLength.getValue());
        }
        if (identity != null) {
            sb.append("\nPSKIdentity:");
            sb.append(ArrayConverter.bytesToHexString(identity.getValue()));
        }
        return sb.toString();
    }

    @Override
    public ECDHClientComputations getComputations() {
        return computations;
    }

    public ModifiableByteArray getIdentity() {
        return identity;
    }

    public void setIdentity(ModifiableByteArray identity) {
        this.identity = identity;
    }

    public void setIdentity(byte[] identity) {
        this.identity = ModifiableVariableFactory.safelySetValue(this.identity, identity);
    }

    public ModifiableByteArray getIdentityLength() {
        return identityLength;
    }

    public void setIdentityLength(ModifiableByteArray identity_length) {
        this.identityLength = identity_length;
    }

    public void setIdentityLength(byte[] identity_length) {
        this.identityLength = ModifiableVariableFactory.safelySetValue(this.identityLength, identity_length);
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
    public ProtocolMessageHandler getHandler(TlsContext context) {
        return new PSKECDHClientKeyExchangeHandler(context);
    }

    @Override
    public String toCompactString() {
        return "PSK_DH_CLIENT_KEY_EXCHANGE";
    }

    @Override
    public void prepareComputations() {
        if (computations == null) {
            computations = new ECDHClientComputations();
        }
    }

    @Override
    public List<ModifiableVariableHolder> getAllModifiableVariableHolders() {
        List<ModifiableVariableHolder> holders = super.getAllModifiableVariableHolders();
        if (computations != null) {
            holders.add(computations);
        }
        return holders;
    }
}
