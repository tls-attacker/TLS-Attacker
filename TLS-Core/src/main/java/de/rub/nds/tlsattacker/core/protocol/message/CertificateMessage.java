/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.message;

import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.handler.CertificateMessageHandler;
import de.rub.nds.tlsattacker.core.protocol.message.cert.CertificateEntry;
import de.rub.nds.tlsattacker.core.protocol.parser.CertificateMessageParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.CertificateMessagePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.CertificateMessageSerializer;
import de.rub.nds.x509attacker.x509.model.X509Certificate;
import jakarta.xml.bind.annotation.XmlElement;
import jakarta.xml.bind.annotation.XmlElementWrapper;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;

@XmlRootElement(name = "Certificate")
public class CertificateMessage extends HandshakeMessage {

    /** request context length */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger requestContextLength;
    /** request context */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.NONE)
    private ModifiableByteArray requestContext;

    /** certificates length */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger certificatesListLength;

    @ModifiableVariableProperty private ModifiableByteArray certificatesListBytes;

    @HoldsModifiableVariable
    @XmlElementWrapper
    @XmlElement(name = "certificatesList")
    private List<CertificateEntry> certificateEntryList;

    public CertificateMessage() {
        super(HandshakeMessageType.CERTIFICATE);
    }

    public ModifiableInteger getCertificatesListLength() {
        return certificatesListLength;
    }

    public void setCertificatesListLength(ModifiableInteger certificatesListLength) {
        this.certificatesListLength = certificatesListLength;
    }

    public void setCertificatesListLength(int length) {
        this.certificatesListLength =
                ModifiableVariableFactory.safelySetValue(certificatesListLength, length);
    }

    public ModifiableByteArray getCertificatesListBytes() {
        return certificatesListBytes;
    }

    public void setCertificatesListBytes(ModifiableByteArray certificatesListBytes) {
        this.certificatesListBytes = certificatesListBytes;
    }

    public void setCertificatesListBytes(byte[] array) {
        this.certificatesListBytes =
                ModifiableVariableFactory.safelySetValue(certificatesListBytes, array);
    }

    public ModifiableInteger getRequestContextLength() {
        return requestContextLength;
    }

    public void setRequestContextLength(ModifiableInteger requestContextLength) {
        this.requestContextLength = requestContextLength;
    }

    public void setRequestContextLength(int length) {
        this.requestContextLength =
                ModifiableVariableFactory.safelySetValue(requestContextLength, length);
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
        sb.append("CertificateMessage:");
        sb.append("\n  Certificates Length: ");
        if (certificatesListLength != null && certificatesListLength.getValue() != null) {
            sb.append(certificatesListLength.getValue());
        } else {
            sb.append("null");
        }
        sb.append("\n  Certificate:\n");
        if (certificatesListBytes != null && certificatesListBytes.getValue() != null) {
            sb.append(ArrayConverter.bytesToHexString(certificatesListBytes.getValue()));
        } else {
            sb.append("null");
        }
        return sb.toString();
    }

    @Override
    public String toShortString() {
        return "CERT";
    }

    @Override
    public CertificateMessageParser getParser(TlsContext tlsContext, InputStream stream) {
        return new CertificateMessageParser(stream, tlsContext);
    }

    @Override
    public CertificateMessagePreparator getPreparator(TlsContext tlsContext) {
        return new CertificateMessagePreparator(tlsContext.getChooser(), this);
    }

    @Override
    public CertificateMessageSerializer getSerializer(TlsContext tlsContext) {
        return new CertificateMessageSerializer(
                this, tlsContext.getChooser().getSelectedProtocolVersion());
    }

    @Override
    public CertificateMessageHandler getHandler(TlsContext tlsContext) {
        return new CertificateMessageHandler(tlsContext);
    }

    public List<CertificateEntry> getCertificateEntryList() {
        return certificateEntryList;
    }

    public void setCertificateEntryList(List<CertificateEntry> certificateEntryList) {
        this.certificateEntryList = certificateEntryList;
    }

    public List<X509Certificate> getX509CertificateListFromEntries() {
        List<X509Certificate> x509CertificateList = new LinkedList<>();
        for (CertificateEntry entry : certificateEntryList) {
            x509CertificateList.add(entry.getX509certificate());
        }
        return x509CertificateList;
    }

    @Override
    public int hashCode() {
        int hash = 7;
        hash = 41 * hash + Objects.hashCode(this.requestContextLength);
        hash = 41 * hash + Objects.hashCode(this.requestContext);
        hash = 41 * hash + Objects.hashCode(this.certificatesListLength);
        hash = 41 * hash + Objects.hashCode(this.certificatesListBytes);
        hash = 41 * hash + Objects.hashCode(this.certificateEntryList);
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
        final CertificateMessage other = (CertificateMessage) obj;
        if (!Objects.equals(this.requestContextLength, other.requestContextLength)) {
            return false;
        }
        if (!Objects.equals(this.requestContext, other.requestContext)) {
            return false;
        }
        if (!Objects.equals(this.certificatesListLength, other.certificatesListLength)) {
            return false;
        }
        if (!Objects.equals(this.certificatesListBytes, other.certificatesListBytes)) {
            return false;
        }
        return Objects.equals(this.certificateEntryList, other.certificateEntryList);
    }
}
