/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.message;

import de.rub.nds.asn1.parser.ParserException;
import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.tlsattacker.core.certificate.ocsp.OCSPResponse;
import de.rub.nds.tlsattacker.core.certificate.ocsp.OCSPResponseParser;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.handler.CertificateStatusHandler;
import de.rub.nds.tlsattacker.core.protocol.parser.CertificateStatusParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.CertificateStatusPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.CertificateStatusSerializer;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.IOException;
import java.io.InputStream;
import java.util.Objects;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

@XmlRootElement(name = "CertificateStatus")
public class CertificateStatusMessage extends HandshakeMessage<CertificateStatusMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger certificateStatusType;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger ocspResponseLength;

    @ModifiableVariableProperty private ModifiableByteArray ocspResponseBytes;

    public CertificateStatusMessage() {
        super(HandshakeMessageType.CERTIFICATE_STATUS);
    }

    @Override
    public CertificateStatusHandler getHandler(TlsContext tlsContext) {
        return new CertificateStatusHandler(tlsContext);
    }

    @Override
    public CertificateStatusParser getParser(TlsContext tlsContext, InputStream stream) {
        return new CertificateStatusParser(stream, tlsContext);
    }

    @Override
    public CertificateStatusPreparator getPreparator(TlsContext tlsContext) {
        return new CertificateStatusPreparator(tlsContext.getChooser(), this);
    }

    @Override
    public CertificateStatusSerializer getSerializer(TlsContext tlsContext) {
        return new CertificateStatusSerializer(this);
    }

    @Override
    public String toString() {
        OCSPResponse response = null;
        if (getOcspResponseBytes() != null) {
            try {
                response = OCSPResponseParser.parseResponse(getOcspResponseBytes().getValue());
            } catch (IOException | ParserException e) {
                LOGGER.error(
                        "Could not parse embedded OCSP response in CertificateStatusMessage." + e);
            }
        }
        StringBuilder builder = new StringBuilder();
        builder.append("CertificateStatusMessage:");
        if (response != null) {
            try {
                builder.append("\n ").append(response.toString());
            } catch (Exception e) {
                throw new RuntimeException(
                        "Could not print parsed OCSP response in CertificateStatusMessage.");
            }
        } else {
            builder.append("\n null");
        }
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
