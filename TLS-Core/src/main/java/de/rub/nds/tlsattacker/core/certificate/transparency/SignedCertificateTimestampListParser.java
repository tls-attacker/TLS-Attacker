/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.certificate.transparency;

import de.rub.nds.tlsattacker.core.protocol.Parser;
import org.bouncycastle.crypto.tls.Certificate;

public class SignedCertificateTimestampListParser extends Parser<SignedCertificateTimestampList> {

    private boolean isPreCertificateSct;
    private Certificate certificateChain;

    /**
     * Constructor for the Parser
     *
     * @param startposition
     *                      Position in the array from which the Parser should start working
     * @param array
     */
    public SignedCertificateTimestampListParser(int startposition, byte[] array, Certificate certificateChain,
        boolean isPreCertificateSct) {
        super(startposition, array);

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
        while (getPointer() < length) {

            // Determine length of variable-length encoded SCT entry
            int entryLength = parseIntField(2);

            // Decode and parse Signed Certificate Timestamp list entry
            byte[] encodedEntryData = parseByteArrayField(entryLength);
            SignedCertificateTimestampParser signedCertificateTimestampParser =
                new SignedCertificateTimestampParser(0, encodedEntryData);
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
