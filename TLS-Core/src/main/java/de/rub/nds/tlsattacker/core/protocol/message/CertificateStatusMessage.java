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
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.protocol.handler.CertificateStatusHandler;
import de.rub.nds.tlsattacker.core.protocol.parser.CertificateStatusParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.CertificateStatusPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.CertificateStatusSerializer;
import de.rub.nds.tlsattacker.core.state.Context;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;
import java.util.Objects;

@XmlRootElement(name = "CertificateStatus")
public class CertificateStatusMessage extends HandshakeMessage {

    @ModifiableVariableProperty private ModifiableInteger certificateStatusType;

    @ModifiableVariableProperty(purpose = ModifiableVariableProperty.Purpose.LENGTH)
    private ModifiableInteger ocspResponseLength;

    @ModifiableVariableProperty private ModifiableByteArray ocspResponseBytes;

    public CertificateStatusMessage() {
        super(HandshakeMessageType.CERTIFICATE_STATUS);
    }

    @Override
    public CertificateStatusHandler getHandler(Context context) {
        return new CertificateStatusHandler(context.getTlsContext());
    }

    @Override
    public CertificateStatusParser getParser(Context context, InputStream stream) {
        return new CertificateStatusParser(stream, context.getTlsContext());
    }

    @Override
    public CertificateStatusPreparator getPreparator(Context context) {
        return new CertificateStatusPreparator(context.getChooser(), this);
    }

    @Override
    public CertificateStatusSerializer getSerializer(Context context) {
        return new CertificateStatusSerializer(this);
    }

    @Override
    public String toString() {
        StringBuilder builder = new StringBuilder();
        builder.append("CertificateStatusMessage");
        return builder.toString();
    }

    @Override
    public String toShortString() {
        return "CERT_STAT";
    }

    public ModifiableInteger getCertificateStatusType() {
        return certificateStatusType;
    }

    public void setCertificateStatusType(int certificateStatusType) {
        this.certificateStatusType =
                ModifiableVariableFactory.safelySetValue(
                        this.certificateStatusType, certificateStatusType);
    }

    public void setCertificateStatusType(ModifiableInteger certificateStatusType) {
        this.certificateStatusType = certificateStatusType;
    }

    public ModifiableInteger getOcspResponseLength() {
        return ocspResponseLength;
    }

    public void setOcspResponseLength(int ocspResponseLength) {
        this.ocspResponseLength =
                ModifiableVariableFactory.safelySetValue(
                        this.ocspResponseLength, ocspResponseLength);
    }

    public void setOcspResponseLength(ModifiableInteger ocspResponseLength) {
        this.ocspResponseLength = ocspResponseLength;
    }

    public ModifiableByteArray getOcspResponseBytes() {
        return ocspResponseBytes;
    }

    public void setOcspResponseBytes(byte[] ocspResponseBytes) {
        this.ocspResponseBytes =
                ModifiableVariableFactory.safelySetValue(this.ocspResponseBytes, ocspResponseBytes);
    }

    public void setOcspResponseBytes(ModifiableByteArray ocspResponseBytes) {
        this.ocspResponseBytes = ocspResponseBytes;
    }

    @Override
    public int hashCode() {
        int hash = 7;
        hash = 23 * hash + Objects.hashCode(this.certificateStatusType);
        hash = 23 * hash + Objects.hashCode(this.ocspResponseLength);
        hash = 23 * hash + Objects.hashCode(this.ocspResponseBytes);
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
        final CertificateStatusMessage other = (CertificateStatusMessage) obj;
        if (!Objects.equals(this.certificateStatusType, other.certificateStatusType)) {
            return false;
        }
        if (!Objects.equals(this.ocspResponseLength, other.ocspResponseLength)) {
            return false;
        }
        return Objects.equals(this.ocspResponseBytes, other.ocspResponseBytes);
    }
}
