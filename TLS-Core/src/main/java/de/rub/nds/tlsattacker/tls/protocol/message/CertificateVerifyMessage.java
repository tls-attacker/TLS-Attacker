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
import de.rub.nds.tlsattacker.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.tlsattacker.tls.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.tls.protocol.handler.ProtocolMessageHandler;
import de.rub.nds.tlsattacker.tls.protocol.handler.CertificateVerifyHandler;
import de.rub.nds.tlsattacker.tls.protocol.serializer.CertificateVerifyMessageSerializer;
import de.rub.nds.tlsattacker.tls.protocol.serializer.Serializer;
import de.rub.nds.tlsattacker.tls.workflow.TlsConfig;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;

/**
 *
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 * @author Philip Riese <philip.riese@rub.de>
 */
public class CertificateVerifyMessage extends HandshakeMessage {

    /**
     * selected Signature and Hashalgorithm
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    private ModifiableByteArray signatureHashAlgorithm;
    /**
     * signature length
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger signatureLength;
    /**
     * signature
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.SIGNATURE)
    private ModifiableByteArray signature;

    public CertificateVerifyMessage() {
        super(HandshakeMessageType.CERTIFICATE_VERIFY);
    }

    public CertificateVerifyMessage(TlsConfig tlsConfig) {
        super(tlsConfig, HandshakeMessageType.CERTIFICATE_VERIFY);
    }

    public ModifiableByteArray getSignatureHashAlgorithm() {
        return signatureHashAlgorithm;
    }

    public void setSignatureHashAlgorithm(ModifiableByteArray signatureHashAlgorithm) {
        this.signatureHashAlgorithm = signatureHashAlgorithm;
    }

    public void setSignatureHashAlgorithm(byte[] signatureHashAlgorithm) {
        this.signatureHashAlgorithm = ModifiableVariableFactory.safelySetValue(this.signatureHashAlgorithm,
                signatureHashAlgorithm);
    }

    public ModifiableInteger getSignatureLength() {
        return signatureLength;
    }

    public void setSignatureLength(ModifiableInteger signatureLength) {
        this.signatureLength = signatureLength;
    }

    public void setSignatureLength(int length) {
        this.signatureLength = ModifiableVariableFactory.safelySetValue(this.signatureLength, length);
    }

    public ModifiableByteArray getSignature() {
        return signature;
    }

    public void setSignature(ModifiableByteArray signature) {
        this.signature = signature;
    }

    public void setSignature(byte[] signature) {
        this.signature = ModifiableVariableFactory.safelySetValue(this.signature, signature);
    }

    @Override
    public ProtocolMessageHandler getHandler(TlsContext context) {
        return new CertificateVerifyHandler(context);
    }

    @Override
    public String toCompactString() {
        return handshakeMessageType.getName();
    }
}
