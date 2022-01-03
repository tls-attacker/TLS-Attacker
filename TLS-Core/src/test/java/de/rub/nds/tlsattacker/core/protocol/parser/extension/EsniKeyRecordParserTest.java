/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import static org.junit.Assert.*;

import java.util.LinkedList;
import java.util.List;

import de.rub.nds.tlsattacker.core.config.Config;
import org.junit.Test;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.EsniVersion;
import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EncryptedServerNameIndicationExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EsniKeyRecord;
import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.KeyShareStoreEntry;

public class EsniKeyRecordParserTest {

    private Config config = Config.createConfig();

    @Test
    public void test1() {

        byte[] recordBytes = ArrayConverter.hexStringToByteArray(
            "ff0100124b2a0024001d0020fa572d03e21e15f9ca1aa7fb85f61b9fc78458a78050ac581811863325944412000213010104000000005dcc3a45000000005dda12050000");
        EsniKeyRecordParser parser = new EsniKeyRecordParser(0, recordBytes, config);
        EsniKeyRecord esniKeyRecord = parser.parse();

        byte[] expectedVersion = EsniVersion.DRAFT_2.getDnsKeyRecordVersion().getByteValue();
        byte[] resultVersion = esniKeyRecord.getVersion().getByteValue();

        byte[] expectedChecksum = ArrayConverter.hexStringToByteArray("00124b2a");
        byte[] resultChecksum = esniKeyRecord.getChecksum();

        KeyShareStoreEntry keyShareStoreEntry = new KeyShareStoreEntry();
        keyShareStoreEntry.setGroup(NamedGroup.ECDH_X25519);
        keyShareStoreEntry.setPublicKey(
            ArrayConverter.hexStringToByteArray("fa572d03e21e15f9ca1aa7fb85f61b9fc78458a78050ac581811863325944412"));
        List<KeyShareStoreEntry> expectedKeyList = new LinkedList();
        expectedKeyList.add(keyShareStoreEntry);
        List<KeyShareStoreEntry> resultKeyList = esniKeyRecord.getKeys();

        List<CipherSuite> expectedCipherSuiteList = new LinkedList();
        expectedCipherSuiteList.add(CipherSuite.TLS_AES_128_GCM_SHA256);
        List<CipherSuite> resultCipherSuiteList = esniKeyRecord.getCipherSuites();

        int expectedPaddedLength = 260;
        int resultPaddedLength = esniKeyRecord.getPaddedLength();

        byte[] expectedNotBefore = ArrayConverter.hexStringToByteArray("000000005dcc3a45");
        byte[] resultNotBefore =
            ArrayConverter.longToBytes(esniKeyRecord.getNotBefore(), ExtensionByteLength.ESNI_RECORD_NOT_BEFORE);

        byte[] expectedNotAfter = ArrayConverter.hexStringToByteArray("000000005dda1205");
        byte[] resultNotAfter =
            ArrayConverter.longToBytes(esniKeyRecord.getNotAfter(), ExtensionByteLength.ESNI_RECORD_NOT_AFTER);

        int expectedExtensionsLength = 0;
        int resultExtensionsLength = esniKeyRecord.getExtensions().size();

        assertArrayEquals(expectedVersion, resultVersion);
        assertArrayEquals(expectedChecksum, resultChecksum);

        assertEquals(expectedKeyList.size(), resultKeyList.size());
        byte[] expectedKey;
        byte[] resultKey;
        NamedGroup expectedGroup;
        NamedGroup resultGroup;
        for (int i = 0; i < expectedKeyList.size(); i++) {
            expectedGroup = expectedKeyList.get(i).getGroup();
            resultGroup = resultKeyList.get(i).getGroup();
            expectedKey = expectedKeyList.get(i).getPublicKey();
            resultKey = resultKeyList.get(i).getPublicKey();
            assertEquals(expectedGroup, resultGroup);
            assertArrayEquals(expectedKey, resultKey);
        }

        assertEquals(expectedCipherSuiteList.size(), resultCipherSuiteList.size());
        CipherSuite expectedCipherSuite;
        CipherSuite resultCipherSuite;
        for (int i = 0; i < resultCipherSuiteList.size(); i++) {
            expectedCipherSuite = expectedCipherSuiteList.get(i);
            resultCipherSuite = resultCipherSuiteList.get(i);
            assertEquals(expectedCipherSuite, resultCipherSuite);
        }

        assertEquals(expectedPaddedLength, resultPaddedLength);
        assertArrayEquals(expectedNotBefore, resultNotBefore);
        assertArrayEquals(expectedNotAfter, resultNotAfter);
        assertEquals(expectedExtensionsLength, resultExtensionsLength);
    }

    @Test
    public void test2() {

        byte[] recordBytes = ArrayConverter.hexStringToByteArray(
            "ff0100124b2a0024001d0020fa572d03e21e15f9ca1aa7fb85f61b9fc78458a78050ac5818118633259444120004130113020104000000005dcc3a45000000005dda12050000");
        EsniKeyRecordParser parser = new EsniKeyRecordParser(0, recordBytes, config);
        EsniKeyRecord esniKeyRecord = parser.parse();

        byte[] expectedVersion = EsniVersion.DRAFT_2.getDnsKeyRecordVersion().getByteValue();
        byte[] resultVersion = esniKeyRecord.getVersion().getByteValue();

        byte[] expectedChecksum = ArrayConverter.hexStringToByteArray("00124b2a");
        byte[] resultChecksum = esniKeyRecord.getChecksum();

        KeyShareStoreEntry keyShareStoreEntry = new KeyShareStoreEntry();
        keyShareStoreEntry.setGroup(NamedGroup.ECDH_X25519);
        keyShareStoreEntry.setPublicKey(
            ArrayConverter.hexStringToByteArray("fa572d03e21e15f9ca1aa7fb85f61b9fc78458a78050ac581811863325944412"));
        List<KeyShareStoreEntry> expectedKeyList = new LinkedList();
        expectedKeyList.add(keyShareStoreEntry);
        List<KeyShareStoreEntry> resultKeyList = esniKeyRecord.getKeys();

        List<CipherSuite> expectedCipherSuiteList = new LinkedList();
        expectedCipherSuiteList.add(CipherSuite.TLS_AES_128_GCM_SHA256);
        expectedCipherSuiteList.add(CipherSuite.TLS_AES_256_GCM_SHA384);

        List<CipherSuite> resultCipherSuiteList = esniKeyRecord.getCipherSuites();

        int expectedPaddedLength = 260;
        int resultPaddedLength = esniKeyRecord.getPaddedLength();

        byte[] expectedNotBefore = ArrayConverter.hexStringToByteArray("000000005dcc3a45");
        byte[] resultNotBefore =
            ArrayConverter.longToBytes(esniKeyRecord.getNotBefore(), ExtensionByteLength.ESNI_RECORD_NOT_BEFORE);

        byte[] expectedNotAfter = ArrayConverter.hexStringToByteArray("000000005dda1205");
        byte[] resultNotAfter =
            ArrayConverter.longToBytes(esniKeyRecord.getNotAfter(), ExtensionByteLength.ESNI_RECORD_NOT_AFTER);

        int expectedExtensionsLength = 0;
        int resultExtensionsLength = esniKeyRecord.getExtensions().size();

        assertArrayEquals(expectedVersion, resultVersion);
        assertArrayEquals(expectedChecksum, resultChecksum);

        assertEquals(expectedKeyList.size(), resultKeyList.size());
        byte[] expectedKey;
        byte[] resultKey;
        NamedGroup expectedGroup;
        NamedGroup resultGroup;
        for (int i = 0; i < expectedKeyList.size(); i++) {
            expectedGroup = expectedKeyList.get(i).getGroup();
            resultGroup = resultKeyList.get(i).getGroup();
            expectedKey = expectedKeyList.get(i).getPublicKey();
            resultKey = resultKeyList.get(i).getPublicKey();
            assertEquals(expectedGroup, resultGroup);
            assertArrayEquals(expectedKey, resultKey);
        }

        assertEquals(expectedCipherSuiteList.size(), resultCipherSuiteList.size());
        CipherSuite expectedCipherSuite;
        CipherSuite resultCipherSuite;
        for (int i = 0; i < expectedCipherSuiteList.size(); i++) {
            expectedCipherSuite = expectedCipherSuiteList.get(i);
            resultCipherSuite = resultCipherSuiteList.get(i);
            assertEquals(expectedCipherSuite, resultCipherSuite);
        }

        assertEquals(expectedPaddedLength, resultPaddedLength);
        assertArrayEquals(expectedNotBefore, resultNotBefore);
        assertArrayEquals(expectedNotAfter, resultNotAfter);
        assertEquals(expectedExtensionsLength, resultExtensionsLength);
    }

    @Test
    public void test3() {
        byte[] recordBytes = ArrayConverter.hexStringToByteArray(
            "ff0100124b2a0046001d0020fa572d03e21e15f9ca1aa7fb85f61b9fc78458a78050ac581811863325944412001E001Efa572d03e21e15f9ca1aa7fb85f61b9fc78458a78050ac581811863325940004130113020104000000005dcc3a45000000005dda12050000");

        EsniKeyRecordParser parser = new EsniKeyRecordParser(0, recordBytes, config);
        EsniKeyRecord esniKeyRecord = parser.parse();

        byte[] expectedVersion = EsniVersion.DRAFT_2.getDnsKeyRecordVersion().getByteValue();
        byte[] resultVersion = esniKeyRecord.getVersion().getByteValue();

        byte[] expectedChecksum = ArrayConverter.hexStringToByteArray("00124b2a");
        byte[] resultChecksum = esniKeyRecord.getChecksum();

        List<KeyShareStoreEntry> expectedKeyList = new LinkedList();

        KeyShareStoreEntry keyShareStoreEntry1 = new KeyShareStoreEntry();
        keyShareStoreEntry1.setGroup(NamedGroup.ECDH_X25519);
        keyShareStoreEntry1.setPublicKey(
            ArrayConverter.hexStringToByteArray("fa572d03e21e15f9ca1aa7fb85f61b9fc78458a78050ac581811863325944412"));
        expectedKeyList.add(keyShareStoreEntry1);

        KeyShareStoreEntry keyShareStoreEntry2 = new KeyShareStoreEntry();
        keyShareStoreEntry2.setGroup(NamedGroup.ECDH_X448);
        keyShareStoreEntry2.setPublicKey(
            ArrayConverter.hexStringToByteArray("fa572d03e21e15f9ca1aa7fb85f61b9fc78458a78050ac58181186332594"));
        expectedKeyList.add(keyShareStoreEntry2);

        List<KeyShareStoreEntry> resultKeyList = esniKeyRecord.getKeys();

        List<CipherSuite> expectedCipherSuiteList = new LinkedList();
        expectedCipherSuiteList.add(CipherSuite.TLS_AES_128_GCM_SHA256);
        expectedCipherSuiteList.add(CipherSuite.TLS_AES_256_GCM_SHA384);

        List<CipherSuite> resultCipherSuiteList = esniKeyRecord.getCipherSuites();

        int expectedPaddedLength = 260;
        int resultPaddedLength = esniKeyRecord.getPaddedLength();

        byte[] expectedNotBefore = ArrayConverter.hexStringToByteArray("000000005dcc3a45");
        byte[] resultNotBefore =
            ArrayConverter.longToBytes(esniKeyRecord.getNotBefore(), ExtensionByteLength.ESNI_RECORD_NOT_BEFORE);

        byte[] expectedNotAfter = ArrayConverter.hexStringToByteArray("000000005dda1205");
        byte[] resultNotAfter =
            ArrayConverter.longToBytes(esniKeyRecord.getNotAfter(), ExtensionByteLength.ESNI_RECORD_NOT_AFTER);

        int expectedExtensionsLength = 0;
        int resultExtensionsLength = esniKeyRecord.getExtensions().size();

        assertArrayEquals(expectedVersion, resultVersion);
        assertArrayEquals(expectedChecksum, resultChecksum);

        assertEquals(expectedKeyList.size(), resultKeyList.size());
        byte[] expectedKey;
        byte[] resultKey;
        NamedGroup expectedGroup;
        NamedGroup resultGroup;
        for (int i = 0; i < expectedKeyList.size(); i++) {
            expectedGroup = expectedKeyList.get(i).getGroup();
            resultGroup = resultKeyList.get(i).getGroup();
            expectedKey = expectedKeyList.get(i).getPublicKey();
            resultKey = resultKeyList.get(i).getPublicKey();
            assertEquals(expectedGroup, resultGroup);
            assertArrayEquals(expectedKey, resultKey);
        }

        assertEquals(expectedCipherSuiteList.size(), resultCipherSuiteList.size());
        CipherSuite expectedCipherSuite;
        CipherSuite resultCipherSuite;
        for (int i = 0; i < expectedCipherSuiteList.size(); i++) {
            expectedCipherSuite = expectedCipherSuiteList.get(i);
            resultCipherSuite = resultCipherSuiteList.get(i);
            assertEquals(expectedCipherSuite, resultCipherSuite);
        }

        assertEquals(expectedPaddedLength, resultPaddedLength);
        assertArrayEquals(expectedNotBefore, resultNotBefore);
        assertArrayEquals(expectedNotAfter, resultNotAfter);
        assertEquals(expectedExtensionsLength, resultExtensionsLength);

    }

    @Test
    public void test4() {

        byte[] recordBytes = ArrayConverter.hexStringToByteArray(
            "ff0100124b2a0024001d0020fa572d03e21e15f9ca1aa7fb85f61b9fc78458a78050ac581811863325944412000213010104000000005dcc3a45000000005dda12050014ffce0010a7284c9a52f15c13644b947261774657");
        EsniKeyRecordParser parser = new EsniKeyRecordParser(0, recordBytes, config);
        EsniKeyRecord esniKeyRecord = parser.parse();

        byte[] expectedVersion = EsniVersion.DRAFT_2.getDnsKeyRecordVersion().getByteValue();
        byte[] resultVersion = esniKeyRecord.getVersion().getByteValue();

        byte[] expectedChecksum = ArrayConverter.hexStringToByteArray("00124b2a");
        byte[] resultChecksum = esniKeyRecord.getChecksum();

        KeyShareStoreEntry keyShareStoreEntry = new KeyShareStoreEntry();
        keyShareStoreEntry.setGroup(NamedGroup.ECDH_X25519);
        keyShareStoreEntry.setPublicKey(
            ArrayConverter.hexStringToByteArray("fa572d03e21e15f9ca1aa7fb85f61b9fc78458a78050ac581811863325944412"));
        List<KeyShareStoreEntry> expectedKeyList = new LinkedList();
        expectedKeyList.add(keyShareStoreEntry);
        List<KeyShareStoreEntry> resultKeyList = esniKeyRecord.getKeys();

        List<CipherSuite> expectedCipherSuiteList = new LinkedList();
        expectedCipherSuiteList.add(CipherSuite.TLS_AES_128_GCM_SHA256);
        List<CipherSuite> resultCipherSuiteList = esniKeyRecord.getCipherSuites();

        int expectedPaddedLength = 260;
        int resultPaddedLength = esniKeyRecord.getPaddedLength();

        byte[] expectedNotBefore = ArrayConverter.hexStringToByteArray("000000005dcc3a45");
        byte[] resultNotBefore =
            ArrayConverter.longToBytes(esniKeyRecord.getNotBefore(), ExtensionByteLength.ESNI_RECORD_NOT_BEFORE);

        byte[] expectedNotAfter = ArrayConverter.hexStringToByteArray("000000005dda1205");
        byte[] resultNotAfter =
            ArrayConverter.longToBytes(esniKeyRecord.getNotAfter(), ExtensionByteLength.ESNI_RECORD_NOT_AFTER);

        byte[] expectedExtensionNonce = ArrayConverter.hexStringToByteArray("a7284c9a52f15c13644b947261774657");
        EncryptedServerNameIndicationExtensionMessage resultExtension =
            (EncryptedServerNameIndicationExtensionMessage) esniKeyRecord.getExtensions().get(0);
        byte[] resultExtensionNonce = resultExtension.getServerNonce().getOriginalValue();

        int expectedExtensionsLength = 1;
        int resultExtensionsLength = esniKeyRecord.getExtensions().size();

        assertArrayEquals(expectedVersion, resultVersion);
        assertArrayEquals(expectedChecksum, resultChecksum);

        assertEquals(expectedKeyList.size(), resultKeyList.size());
        byte[] expectedKey;
        byte[] resultKey;
        NamedGroup expectedGroup;
        NamedGroup resultGroup;
        for (int i = 0; i < expectedKeyList.size(); i++) {
            expectedGroup = expectedKeyList.get(i).getGroup();
            resultGroup = resultKeyList.get(i).getGroup();
            expectedKey = expectedKeyList.get(i).getPublicKey();
            resultKey = resultKeyList.get(i).getPublicKey();
            assertEquals(expectedGroup, resultGroup);
            assertArrayEquals(expectedKey, resultKey);
        }

        assertEquals(expectedCipherSuiteList.size(), resultCipherSuiteList.size());
        CipherSuite expectedCipherSuite;
        CipherSuite resultCipherSuite;
        for (int i = 0; i < resultCipherSuiteList.size(); i++) {
            expectedCipherSuite = expectedCipherSuiteList.get(i);
            resultCipherSuite = resultCipherSuiteList.get(i);
            assertEquals(expectedCipherSuite, resultCipherSuite);
        }

        assertEquals(expectedPaddedLength, resultPaddedLength);
        assertArrayEquals(expectedNotBefore, resultNotBefore);
        assertArrayEquals(expectedNotAfter, resultNotAfter);
        assertEquals(expectedExtensionsLength, resultExtensionsLength);
        assertArrayEquals(expectedExtensionNonce, resultExtensionNonce);

    }
}