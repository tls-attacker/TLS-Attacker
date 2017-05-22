/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.protocol.handler.CertificateHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.ProtocolMessageHandler;
import de.rub.nds.tlsattacker.core.protocol.serializer.CertificateMessageSerializer;
import de.rub.nds.tlsattacker.core.protocol.serializer.Serializer;
import de.rub.nds.tlsattacker.core.workflow.TlsConfig;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import javax.xml.bind.annotation.XmlRootElement;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
@XmlRootElement
public class CertificateMessage extends HandshakeMessage {

    /**
     * certificates length
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger certificatesLength;

    @ModifiableVariableProperty(format = ModifiableVariableProperty.Format.ASN1, type = ModifiableVariableProperty.Type.CERTIFICATE)
    private ModifiableByteArray x509CertificateBytes;

    public CertificateMessage() {
        super(HandshakeMessageType.CERTIFICATE);
        // status_request & signed_certificate_timestamp & server_certificate_type
        // extensions can be added, but not implemented
    }

    public CertificateMessage(TlsConfig tlsConfig) {
        super(tlsConfig, HandshakeMessageType.CERTIFICATE);
    }

    public ModifiableInteger getCertificatesLength() {
        return certificatesLength;
    }

    public void setCertificatesLength(ModifiableInteger certificatesLength) {
        this.certificatesLength = certificatesLength;
    }

    public void setCertificatesLength(int length) {
        this.certificatesLength = ModifiableVariableFactory.safelySetValue(certificatesLength, length);
    }

    public ModifiableByteArray getX509CertificateBytes() {
        return x509CertificateBytes;
    }

    public void setX509CertificateBytes(ModifiableByteArray x509CertificateBytes) {
        this.x509CertificateBytes = x509CertificateBytes;
    }

    public void setX509CertificateBytes(byte[] array) {
        this.x509CertificateBytes = ModifiableVariableFactory.safelySetValue(x509CertificateBytes, array);
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder(super.toString());
        if (certificatesLength != null) {
            sb.append("\n  Certificates Length: ");
            sb.append(certificatesLength.getValue());
        }
        if (x509CertificateBytes != null) {
            sb.append("\n  Certificate:\n");
            sb.append(ArrayConverter.bytesToHexString(x509CertificateBytes.getValue()));
        }
        // Ohne TLS Version Abfrage ?
        if (getExtensions() == null) {
            sb.append("\n  Extensions: null");
        } else {
            sb.append("\n  Extensions: ");
            for (ExtensionMessage e : getExtensions()) {
                sb.append(e.toString());
            }
        }
        return sb.toString();
    }

    @Override
    public ProtocolMessageHandler getHandler(TlsContext context) {
        return new CertificateHandler(context);
    }
}
