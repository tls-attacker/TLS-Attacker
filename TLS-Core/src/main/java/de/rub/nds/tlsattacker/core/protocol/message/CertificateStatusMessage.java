/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
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
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.protocol.handler.CertificateStatusHandler;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.io.IOException;
import javax.xml.bind.annotation.XmlRootElement;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

@XmlRootElement(name = "CertificateStatus")
public class CertificateStatusMessage extends HandshakeMessage {

    private static final Logger LOGGER = LogManager.getLogger();

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger certificateStatusType;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger ocspResponseLength;

    @ModifiableVariableProperty
    private ModifiableByteArray ocspResponseBytes;

    public CertificateStatusMessage() {
        super(HandshakeMessageType.CERTIFICATE_STATUS);
    }

    public CertificateStatusMessage(Config tlsConfig) {
        super(tlsConfig, HandshakeMessageType.CERTIFICATE_STATUS);
    }

    @Override
    public CertificateStatusHandler getHandler(TlsContext context) {
        return new CertificateStatusHandler(context);
    }

    @Override
    public String toString() {
        OCSPResponse response = null;
        if (getOcspResponseBytes() != null) {
            try {
                response = OCSPResponseParser.parseResponse(getOcspResponseBytes().getValue());
            } catch (IOException | ParserException e) {
                LOGGER.error("Could not parse embedded OCSP response in CertificateStatusMessage." + e);
            }
        }
        StringBuilder builder = new StringBuilder();
        builder.append("CertificateStatusMessage:");
        if (response != null) {
            try {
                builder.append("\n ").append(response.toString());
            } catch (Exception e) {
                throw new RuntimeException("Could not print parsed OCSP response in CertificateStatusMessage.");
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
            ModifiableVariableFactory.safelySetValue(this.certificateStatusType, certificateStatusType);
    }

    public void setCertificateStatusType(ModifiableInteger certificateStatusType) {
        this.certificateStatusType = certificateStatusType;
    }

    public ModifiableInteger getOcspResponseLength() {
        return ocspResponseLength;
    }

    public void setOcspResponseLength(int ocspResponseLength) {
        this.ocspResponseLength = ModifiableVariableFactory.safelySetValue(this.ocspResponseLength, ocspResponseLength);
    }

    public void setOcspResponseLength(ModifiableInteger ocspResponseLength) {
        this.ocspResponseLength = ocspResponseLength;
    }

    public ModifiableByteArray getOcspResponseBytes() {
        return ocspResponseBytes;
    }

    public void setOcspResponseBytes(byte[] ocspResponseBytes) {
        this.ocspResponseBytes = ModifiableVariableFactory.safelySetValue(this.ocspResponseBytes, ocspResponseBytes);
    }

    public void setOcspResponseBytes(ModifiableByteArray ocspResponseBytes) {
        this.ocspResponseBytes = ocspResponseBytes;
    }
}
