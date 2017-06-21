/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator;

import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import java.util.Arrays;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class CertificateMessagePreparator extends HandshakeMessagePreparator<CertificateMessage> {

    private final CertificateMessage msg;

    public CertificateMessagePreparator(Chooser chooser, CertificateMessage msg) {
        super(chooser, msg);
        this.msg = msg;
    }

    @Override
    public void prepareHandshakeMessageContents() {
        byte[] encodedCert = getEncodedCert();
        msg.setX509CertificateBytes(encodedCert);
        msg.setCertificatesLength(msg.getX509CertificateBytes().getValue().length);
    }

    private byte[] getEncodedCert() {
        return Arrays.copyOfRange(chooser.getConfig().getOurCertificate(), HandshakeByteLength.CERTIFICATES_LENGTH,
                chooser.getConfig().getOurCertificate().length);

    }
}
