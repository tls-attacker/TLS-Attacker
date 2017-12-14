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
import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.certificate.CertificateByteChooser;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.protocol.handler.CertificateHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.ProtocolMessageHandler;
import de.rub.nds.tlsattacker.core.protocol.message.Cert.CertificateEntry;
import de.rub.nds.tlsattacker.core.protocol.message.Cert.CertificatePair;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.LinkedList;
import java.util.List;
import javax.xml.bind.annotation.XmlRootElement;
import org.bouncycastle.crypto.tls.Certificate;

@XmlRootElement
public class CertificateMessage extends HandshakeMessage {

    /**
     * request context length
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger requestContextLength;
    /**
     * request context
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.NONE)
    private ModifiableByteArray requestContext;

    /**
     * certificates length
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger certificatesListLength;

    @ModifiableVariableProperty
    private ModifiableByteArray certificatesListBytes;

    @HoldsModifiableVariable
    private List<CertificatePair> certificatesList;

    @HoldsModifiableVariable
    private List<CertificateEntry> certificatesListAsEntry;

    public CertificateMessage() {
        super(HandshakeMessageType.CERTIFICATE);
        certificatesList = new LinkedList<>();
    }

    public CertificateMessage(Config tlsConfig) {
        super(tlsConfig, HandshakeMessageType.CERTIFICATE);
        certificatesList = new LinkedList<>();
        try {
            Certificate cert = getCertificate(tlsConfig);
            for (org.bouncycastle.asn1.x509.Certificate singleCert : cert.getCertificateList()) {
                CertificatePair pair = new CertificatePair();
                pair.setCertificateConfig(singleCert.getEncoded());
                certificatesList.add(pair);
            }
        } catch (IOException ex) {
            LOGGER.warn("Could not parse configured Certificate into a real Certificate. Just sending bytes as they are (with added Length field)");
            CertificatePair pair = new CertificatePair();
            pair.setCertificateConfig(CertificateByteChooser.chooseCertificateType(tlsConfig));
            certificatesList.add(pair);
        }
    }

    private Certificate getCertificate(Config config) throws IOException {
        return Certificate.parse(new ByteArrayInputStream(CertificateByteChooser.chooseCertificateType(config)));
    }

    public ModifiableInteger getCertificatesListLength() {
        return certificatesListLength;
    }

    public void setCertificatesListLength(ModifiableInteger certificatesListLength) {
        this.certificatesListLength = certificatesListLength;
    }

    public void setCertificatesListLength(int length) {
        this.certificatesListLength = ModifiableVariableFactory.safelySetValue(certificatesListLength, length);
    }

    public ModifiableByteArray getCertificatesListBytes() {
        return certificatesListBytes;
    }

    public void setCertificatesListBytes(ModifiableByteArray certificatesListBytes) {
        this.certificatesListBytes = certificatesListBytes;
    }

    public void setCertificatesListBytes(byte[] array) {
        this.certificatesListBytes = ModifiableVariableFactory.safelySetValue(certificatesListBytes, array);
    }

    public List<CertificatePair> getCertificatesList() {
        return certificatesList;
    }

    public void setCertificatesList(List<CertificatePair> certificatesList) {
        this.certificatesList = certificatesList;
    }

    public void addCertificateList(CertificatePair CertificatePair) {
        if (this.certificatesList == null) {
            certificatesList = new LinkedList<>();
        }
        this.certificatesList.add(CertificatePair);
    }

    public List<CertificateEntry> getCertificatesListAsEntry() {
        return certificatesListAsEntry;
    }

    public void setCertificatesListAsEntry(List<CertificateEntry> certificatesListAsEntry) {
        this.certificatesListAsEntry = certificatesListAsEntry;
    }

    public void addCertificateList(CertificateEntry certificateEntry) {
        if (this.certificatesListAsEntry == null) {
            certificatesListAsEntry = new LinkedList<>();
        }
        this.certificatesListAsEntry.add(certificateEntry);
    }

    public ModifiableInteger getRequestContextLength() {
        return requestContextLength;
    }

    public void setRequestContextLength(ModifiableInteger requestContextLength) {
        this.requestContextLength = requestContextLength;
    }

    public void setRequestContextLength(int length) {
        this.requestContextLength = ModifiableVariableFactory.safelySetValue(requestContextLength, length);
    }

    public ModifiableByteArray getRequestContext() {
        return requestContext;
    }

    public void setRequestContext(ModifiableByteArray requestContext) {
        this.requestContext = requestContext;
    }

    public void setRequestContext(byte[] array) {
        this.requestContext = ModifiableVariableFactory.safelySetValue(requestContext, array);
    }

    public boolean hasRequestContext() {
        return requestContextLength.getValue() > 0;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("\nCertificateMessage:");
        sb.append("\n  Certificates Length: ");
        if (certificatesListLength != null) {
            sb.append(certificatesListLength.getValue());
        } else {
            sb.append("null");
        }
        sb.append("\n  Certificate:\n");
        if (certificatesListBytes != null) {
            sb.append(ArrayConverter.bytesToHexString(certificatesListBytes.getValue()));
        } else {
            sb.append("null");
        }
        return sb.toString();
    }

    @Override
    public ProtocolMessageHandler getHandler(TlsContext context) {
        return new CertificateHandler(context);
    }
}
