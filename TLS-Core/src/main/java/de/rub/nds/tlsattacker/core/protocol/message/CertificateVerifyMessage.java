/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.handler.CertificateVerifyHandler;
import de.rub.nds.tlsattacker.core.protocol.parser.CertificateVerifyParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.CertificateVerifyPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.CertificateVerifySerializer;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;
import java.util.Objects;

@XmlRootElement(name = "CertificateVerify")
public class CertificateVerifyMessage extends HandshakeMessage<CertificateVerifyMessage> {

    /** selected Signature and Hashalgorithm */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    private ModifiableByteArray signatureHashAlgorithm;
    /** signature length */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger signatureLength;
    /** signature */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.SIGNATURE)
    private ModifiableByteArray signature;

    public CertificateVerifyMessage() {
        super(HandshakeMessageType.CERTIFICATE_VERIFY);
    }

    public ModifiableByteArray getSignatureHashAlgorithm() {
        return signatureHashAlgorithm;
    }

    public void setSignatureHashAlgorithm(ModifiableByteArray signatureHashAlgorithm) {
        this.signatureHashAlgorithm = signatureHashAlgorithm;
    }

    public void setSignatureHashAlgorithm(byte[] signatureHashAlgorithm) {
        this.signatureHashAlgorithm =
                ModifiableVariableFactory.safelySetValue(
                        this.signatureHashAlgorithm, signatureHashAlgorithm);
    }

    public ModifiableInteger getSignatureLength() {
        return signatureLength;
    }

    public void setSignatureLength(ModifiableInteger signatureLength) {
        this.signatureLength = signatureLength;
    }

    public void setSignatureLength(int length) {
        this.signatureLength =
                ModifiableVariableFactory.safelySetValue(this.signatureLength, length);
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
    public String toString() {
        StringBuilder builder = new StringBuilder();
        builder.append("CertificateVerifyMessage:");
        builder.append("\n  SignatureAndHashAlgorithm: ");
        if (signatureHashAlgorithm != null && signatureHashAlgorithm.getValue() != null) {
            builder.append(ArrayConverter.bytesToHexString(signatureHashAlgorithm.getValue()));
        } else {
            builder.append("null");
        }
        builder.append("\n  Signature Length: ");
        if (signatureLength != null && signatureLength.getValue() != null) {
            builder.append(signatureLength.getValue());
        } else {
            builder.append("null");
        }
        builder.append("\n  Signature: ");
        if (signature != null && signature.getValue() != null) {
            builder.append(ArrayConverter.bytesToHexString(signature.getValue()));
        } else {
            builder.append("null");
        }
        return builder.toString();
    }

    @Override
    public String toShortString() {
        return "CV";
    }

    @Override
    public CertificateVerifyHandler getHandler(TlsContext tlsContext) {
        return new CertificateVerifyHandler(tlsContext);
    }

    @Override
    public CertificateVerifyParser getParser(TlsContext tlsContext, InputStream stream) {
        return new CertificateVerifyParser(stream, tlsContext);
    }

    @Override
    public CertificateVerifyPreparator getPreparator(TlsContext tlsContext) {
        return new CertificateVerifyPreparator(tlsContext.getChooser(), this);
    }

    @Override
    public CertificateVerifySerializer getSerializer(TlsContext tlsContext) {
        return new CertificateVerifySerializer(
                this, tlsContext.getChooser().getSelectedProtocolVersion());
    }

    @Override
    public int hashCode() {
        int hash = 5;
        hash = 29 * hash + Objects.hashCode(this.signatureHashAlgorithm);
        hash = 29 * hash + Objects.hashCode(this.signatureLength);
        hash = 29 * hash + Objects.hashCode(this.signature);
        return hash;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final CertificateVerifyMessage other = (CertificateVerifyMessage) obj;
        if (!Objects.equals(this.signatureHashAlgorithm, other.signatureHashAlgorithm)) {
            return false;
        }
        if (!Objects.equals(this.signatureLength, other.signatureLength)) {
            return false;
        }
        return Objects.equals(this.signature, other.signature);
    }
}
