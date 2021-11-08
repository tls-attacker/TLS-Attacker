/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.certificate.transparency;

import de.rub.nds.tlsattacker.core.protocol.Parser;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import org.bouncycastle.crypto.tls.Certificate;

public class SignedCertificateTimestampListParser extends Parser<SignedCertificateTimestampList> {

    private final boolean isPreCertificateSct;
    private final Certificate certificateChain;

    /**
     * Constructor for the Parser
     *
     * @param stream
     * @param certificateChain
     * @param isPreCertificateSct
     */
    public SignedCertificateTimestampListParser(InputStream stream, Certificate certificateChain,
            boolean isPreCertificateSct) {
        super(stream);

        this.isPreCertificateSct = isPreCertificateSct;
        this.certificateChain = certificateChain;
    }

    @Override
    public SignedCertificateTimestampList parse() {
        SignedCertificateTimestampList sctList = new SignedCertificateTimestampList();

        org.bouncycastle.asn1.x509.Certificate leafCertificate = certificateChain.getCertificateAt(0);
        org.bouncycastle.asn1.x509.Certificate issuerCertificate = certificateChain.getCertificateAt(1);

        int length = parseIntField(2);

        // Decode and parse every list entry
        while (getBytesLeft() > 0) {

            // Determine length of variable-length encoded SCT entry
            int entryLength = parseIntField(2);

            // Decode and parse Signed Certificate Timestamp list entry
            byte[] encodedEntryData = parseByteArrayField(entryLength);
            SignedCertificateTimestampParser signedCertificateTimestampParser
                    = new SignedCertificateTimestampParser(new ByteArrayInputStream(encodedEntryData));
            SignedCertificateTimestamp sct = signedCertificateTimestampParser.parse();

            // Add certificates required for SCT signature validation
            sct.setCertificate(leafCertificate);
            sct.setIssuerCertificate(issuerCertificate);

            // Add Log-Entry-Type
            if (isPreCertificateSct) {
                sct.setLogEntryType(SignedCertificateTimestampEntryType.PrecertChainEntry);
            } else {
                sct.setLogEntryType(SignedCertificateTimestampEntryType.X509ChainEntry);
            }

            // Add parsed SCT to the SCT-List data structure
            sctList.getCertificateTimestampList().add(sct);
        }

        sctList.setEncodedTimestampList(getAlreadyParsed());
        return sctList;
    }
}
