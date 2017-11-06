/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.message.Cert;

import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import java.util.List;

/**

 */
public class CertificateEntry {

    private byte[] certificate;

    private List<ExtensionMessage> extensions;

    public CertificateEntry(byte[] certificate, List<ExtensionMessage> extensions) {
        this.certificate = certificate;
        this.extensions = extensions;
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
