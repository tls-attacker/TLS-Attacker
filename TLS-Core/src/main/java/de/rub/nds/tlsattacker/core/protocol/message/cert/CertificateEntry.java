/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.message.cert;

import de.rub.nds.modifiablevariable.util.ByteArrayAdapter;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import java.util.List;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;

@XmlAccessorType(XmlAccessType.FIELD)
public class CertificateEntry {

    @XmlJavaTypeAdapter(ByteArrayAdapter.class)
    private byte[] certificate;

    private List<ExtensionMessage> extensions;

    public CertificateEntry(byte[] certificate, List<ExtensionMessage> extensions) {
        this.certificate = certificate;
        this.extensions = extensions;
    }

    public CertificateEntry() {
    }

    public byte[] getCertificate() {
        return certificate;
    }

    public void setCertificate(byte[] certificate) {
        this.certificate = certificate;
    }

    public List<ExtensionMessage> getExtensions() {
        return extensions;
    }

    public void setExtensions(List<ExtensionMessage> extensions) {
        this.extensions = extensions;
    }

}
