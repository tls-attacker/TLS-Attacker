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
import org.bouncycastle.crypto.tls.Certificate;

/**
 * @author Nurullah Erinola <nurullah.erinola@rub.de>
 */
public class CertificateEntry {

    private Certificate certificate;

    private List<ExtensionMessage> extensions;

    public CertificateEntry(Certificate certificate, List<ExtensionMessage> extensions) {
        this.certificate = certificate;
        this.extensions = extensions;
    }

    public Certificate getCertificate() {
        return certificate;
    }

    public void setCertificate(Certificate certificate) {
        this.certificate = certificate;
    }

    public List<ExtensionMessage> getExtensions() {
        return extensions;
    }

    public void setExtensions(List<ExtensionMessage> extensions) {
        this.extensions = extensions;
    }

}
