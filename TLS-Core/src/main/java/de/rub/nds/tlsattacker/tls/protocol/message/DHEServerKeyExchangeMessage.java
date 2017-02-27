/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.message;

import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.tlsattacker.modifiablevariable.biginteger.ModifiableBigInteger;
import de.rub.nds.tlsattacker.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.tlsattacker.tls.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.tls.constants.HashAlgorithm;
import de.rub.nds.tlsattacker.tls.constants.SignatureAlgorithm;
import de.rub.nds.tlsattacker.tls.protocol.handler.ProtocolMessageHandler;
import de.rub.nds.tlsattacker.tls.protocol.handler.DHEServerKeyExchangeHandler;
import de.rub.nds.tlsattacker.tls.workflow.TlsConfig;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import java.math.BigInteger;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 * @author Philip Riese <philip.riese@rub.de>
 */
public class DHEServerKeyExchangeMessage extends ServerKeyExchangeMessage {

    /**
     * DH modulus length
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger pLength;
    /**
     * DH modulus
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.PUBLIC_KEY)
    private ModifiableBigInteger p;
    /**
     * DH generator length
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger gLength;
    /**
     * DH generator
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.PUBLIC_KEY)
    private ModifiableBigInteger g;
    /**
     * public key length
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger publicKeyLength;
    /**
     * public key
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.PUBLIC_KEY)
    private ModifiableBigInteger publicKey;
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

    public DHEServerKeyExchangeMessage() {
        super();
    }

    public DHEServerKeyExchangeMessage(TlsConfig tlsConfig) {
        super(tlsConfig, HandshakeMessageType.SERVER_KEY_EXCHANGE);
    }

    public ModifiableInteger getpLength() {
        return pLength;
    }

    public void setpLength(ModifiableInteger pLength) {
        this.pLength = pLength;
    }

    public void setpLength(Integer pLength) {
        this.pLength = ModifiableVariableFactory.safelySetValue(this.pLength, pLength);
    }

    public ModifiableBigInteger getP() {
        return p;
    }

    public void setP(ModifiableBigInteger p) {
        this.p = p;
    }

    public void setP(BigInteger p) {
        this.p = ModifiableVariableFactory.safelySetValue(this.p, p);
    }

    public ModifiableInteger getgLength() {
        return gLength;
    }

    public void setgLength(ModifiableInteger gLength) {
        this.gLength = gLength;
    }

    public void setgLength(Integer gLength) {
        this.gLength = ModifiableVariableFactory.safelySetValue(this.gLength, gLength);
    }

    public ModifiableBigInteger getG() {
        return g;
    }

    public void setG(ModifiableBigInteger g) {
        this.g = g;
    }

    public void setG(BigInteger g) {
        this.g = ModifiableVariableFactory.safelySetValue(this.g, g);
    }

    public ModifiableBigInteger getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(ModifiableBigInteger publicKey) {
        this.publicKey = publicKey;
    }

    public void setPublicKey(BigInteger publicKey) {
        this.publicKey = ModifiableVariableFactory.safelySetValue(this.publicKey, publicKey);
    }

    public ModifiableInteger getPublicKeyLength() {
        return publicKeyLength;
    }

    public void setPublicKeyLength(ModifiableInteger publicKeyLength) {
        this.publicKeyLength = publicKeyLength;
    }

    public void setPublicKeyLength(int length) {
        this.publicKeyLength = ModifiableVariableFactory.safelySetValue(this.publicKeyLength, length);
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
    
    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(super.toString()).append("\n  Modulus p: ");
        if (p != null) {
            sb.append(p.getValue().toString(16));
        } else {
            sb.append("null");
        }
        sb.append("\n  Generator g: ");
        if (g != null) {
            sb.append(g.getValue().toString(16));
        } else {
            sb.append("null");
        }
        sb.append("\n  Public Key: ");
        if (publicKey != null) {
            sb.append(publicKey.getValue().toString(16));
        } else {
            sb.append("null");
        }
        sb.append("\n  Signature Algorithm: ");
        // signature and hash algorithms are provided only while working with
        // (D)TLS 1.2
        if (this.getHashAlgorithm() != null) {
            sb.append(HashAlgorithm.getHashAlgorithm(this.getHashAlgorithm().getValue())).append(" ");
        }
        if (this.getSignatureAlgorithm() != null) {
            sb.append(SignatureAlgorithm.getSignatureAlgorithm(this.getSignatureAlgorithm().getValue()));
        }
        sb.append("\n  Signature: ");
        if (this.getSignature() != null) {
            sb.append(ArrayConverter.bytesToHexString(this.getSignature().getValue()));
        } else {
            sb.append("null");
        }
        return sb.toString();
    }
}
