package de.rub.nds.tlsattacker.attacks.cca;

import de.rub.nds.tlsattacker.core.crypto.keys.CustomPrivateKey;
import de.rub.nds.tlsattacker.core.crypto.keys.CustomPublicKey;

import java.util.LinkedList;
import java.util.List;

public class CcaCertificateChain {
    private List<byte[]> encodedCertificates;
    private CustomPrivateKey leafCertificatePrivateKey;
    private CustomPublicKey leafCertificatePublicKey;

    CcaCertificateChain() {
        this.encodedCertificates = new LinkedList<>();
    }

    public void appendEncodedCertificate(byte[] encodedCertificate) {
        encodedCertificates.add(encodedCertificate);
    }

    public void setLeafCertificatePrivateKey(CustomPrivateKey leafCertificatePrivateKey) {
        this.leafCertificatePrivateKey = leafCertificatePrivateKey;
    }

    public CustomPrivateKey getLeafCertificatePrivateKey() {
        return leafCertificatePrivateKey;
    }

    public void setLeafCertificatePublicKey(CustomPublicKey leafCertificatePublicKey) {
        this.leafCertificatePublicKey = leafCertificatePublicKey;
    }

    public CustomPublicKey getLeafCertificatePublicKey() {
        return leafCertificatePublicKey;
    }

    public List<byte[]> getEncodedCertificates() {
        return encodedCertificates;
    }

    public void setEncodedCertificates(List<byte[]> encodedCertificates) {
        this.encodedCertificates = encodedCertificates;
    }
}
