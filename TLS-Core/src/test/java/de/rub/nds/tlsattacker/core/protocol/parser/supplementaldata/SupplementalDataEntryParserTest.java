/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.parser.supplementaldata;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.protocol.message.supplementaldata.SupplementalDataEntry;
import java.util.Arrays;
import java.util.Collection;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertTrue;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class SupplementalDataEntryParserTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return Arrays.asList(new Object[][] { { ArrayConverter.hexStringToByteArray("4002000a0008010005aaaaaaaaaa"),
                16386, 10, ArrayConverter.hexStringToByteArray("0008010005aaaaaaaaaa") } });
    }

    private int supplementalDataEntryType;
    private int supplementalDataEntryLength;
    private byte[] supplementalDataEntry;
    private byte[] supplementalDataTestEntry;

    public SupplementalDataEntryParserTest(byte[] supplementalDataTestEntry, int supplementalDataEntryType,
            int supplementalDataEntryLength, byte[] supplementalDataEntry) {
        this.supplementalDataEntryType = supplementalDataEntryType;
        this.supplementalDataEntryLength = supplementalDataEntryLength;
        this.supplementalDataEntry = supplementalDataEntry;
        this.supplementalDataTestEntry = supplementalDataTestEntry;
    }

    @Test
    public void testParse() {
        SupplementalDataEntryParser parser = new SupplementalDataEntryParser(0, supplementalDataTestEntry);
        SupplementalDataEntry entry = parser.parse();
        assertTrue(supplementalDataEntryType == entry.getSupplementalDataEntryType().getValue());
        assertTrue(supplementalDataEntryLength == entry.getSupplementalDataEntryLength().getValue());
        assertArrayEquals(supplementalDataEntry, entry.getSupplementalDataEntry().getValue());
    }

}
