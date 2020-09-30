/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2020 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.certificate.transparency;

import de.rub.nds.asn1.parser.ParserException;

import java.util.Arrays;

public class SignedCertificateTimestampListParser {

    public static SignedCertificateTimestampList parseTimestampList(byte[] encodedTimestampList) throws ParserException {

        SignedCertificateTimestampList sctList = new SignedCertificateTimestampList();
        sctList.setEncodedTimestampList(encodedTimestampList);

        // Extract total length of certificate timestamp list
        int length = encodedTimestampList[0] << 8 | encodedTimestampList[1] & 0x00ff;

        // Use index value to navigate through variable-length encoded SCT list
        // and skip first 2 bytes (length field)
        int index = 2;

        // Decode and parse every list entry
        while (index < length) {

            // Determine length of variable-length encoded SCT entry
            int entryLength = encodedTimestampList[index] << 8 | encodedTimestampList[index + 1] & 0x00ff;

            // Decode and parse Signed Certificate Timestamp list entry
            byte[] encodedEntryData = Arrays.copyOfRange(encodedTimestampList, index + 2, index + entryLength);
            SignedCertificateTimestamp sct = SignedCertificateTimestampParser.parseTimestamp(encodedEntryData);

            // Add parsed SCT to the SCT-List data structure
            sctList.getCertificateTimestampList().add(sct);

            // Adjust index for beginning of next entry
            index += 2 + entryLength;
        }

        return sctList;
    }
}
