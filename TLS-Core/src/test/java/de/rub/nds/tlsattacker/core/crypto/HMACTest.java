/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.crypto;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.MacAlgorithm;
import junit.framework.TestCase;
import org.junit.Test;

import java.security.NoSuchAlgorithmException;

import static org.junit.Assert.assertArrayEquals;

public class HMACTest extends TestCase {

    @Test
    public void testInitSHA() throws NoSuchAlgorithmException {
        byte[] data = ArrayConverter.hexStringToByteArray("01010101010101010101010101010101");
        byte[] secret =
                ArrayConverter.hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEFC0FEDEAD");
        HMAC hmac = new HMAC(MacAlgorithm.HMAC_SHA1);
        hmac.init(secret, data);

        assertArrayEquals(ArrayConverter.hexStringToByteArray("01010101010101010101010101010101"), hmac.getData());

        assertArrayEquals(ArrayConverter.hexStringToByteArray(
                "DEADBEEFC0FEDEADBEEFC0FEDEADBEEFC0FEDEAD0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
                hmac.getSecret());

        assertArrayEquals(ArrayConverter.hexStringToByteArray(
                "5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C"),
                hmac.getOpad());

        assertArrayEquals(ArrayConverter.hexStringToByteArray(
                "36363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636"),
                hmac.getIpad());
    }

    @Test
    public void testInitSHA256() throws NoSuchAlgorithmException {
        byte[] data = ArrayConverter.hexStringToByteArray("01010101010101010101010101010101");
        byte[] secret =
                ArrayConverter.hexStringToByteArray("DEADBEEFC0FFEEDEADBEEFC0FFEEDEADBEEFC0FFEEDEADBEEFC0FFEEDEAD");
        HMAC hmac = new HMAC(MacAlgorithm.HMAC_SHA256);
        hmac.init(secret, data);

        assertArrayEquals(ArrayConverter.hexStringToByteArray("01010101010101010101010101010101"), hmac.getData());

        assertArrayEquals(ArrayConverter.hexStringToByteArray(
                "DEADBEEFC0FFEEDEADBEEFC0FFEEDEADBEEFC0FFEEDEADBEEFC0FFEEDEAD00000000000000000000000000000000000000000000000000000000000000000000"),
                hmac.getSecret());

        assertArrayEquals(ArrayConverter.hexStringToByteArray(
                "5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C"),
                hmac.getOpad());

        assertArrayEquals(ArrayConverter.hexStringToByteArray(
                "36363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636"),
                hmac.getIpad());
    }

    @Test
    public void testInitSHA384() throws NoSuchAlgorithmException {
        byte[] data = ArrayConverter.hexStringToByteArray("01010101010101010101010101010101");
        byte[] secret =
                ArrayConverter.hexStringToByteArray("DEADBEEFC0FFEEDEADBEEFC0FFEEDEADBEEFC0FFEEDEADBEEFC0FFEEDEAD");
        HMAC hmac = new HMAC(MacAlgorithm.HMAC_SHA384);
        hmac.init(secret, data);

        assertArrayEquals(ArrayConverter.hexStringToByteArray("01010101010101010101010101010101"), hmac.getData());
        assertArrayEquals(ArrayConverter.hexStringToByteArray(
                "DEADBEEFC0FFEEDEADBEEFC0FFEEDEADBEEFC0FFEEDEADBEEFC0FFEEDEAD0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
                hmac.getSecret());

        assertArrayEquals(ArrayConverter.hexStringToByteArray(
                "5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C"),
                hmac.getOpad());

        assertArrayEquals(ArrayConverter.hexStringToByteArray(
                "3636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636"),
                hmac.getIpad());
    }

    @Test
    public void testComputeMD5() throws NoSuchAlgorithmException {
        byte[] data = ArrayConverter.hexStringToByteArray("01010101010101010101010101010101");
        byte[] secret =
                ArrayConverter.hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEFC0FEDEAD");
        HMAC hmac = new HMAC(MacAlgorithm.HMAC_MD5);
        hmac.init(secret, data);
        hmac.compute();
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray("6af39a238e82675131e6a383f801674e"),
                hmac.getHmac());
    }

    @Test
    public void testComputeSHA() throws NoSuchAlgorithmException {
        byte[] data = ArrayConverter.hexStringToByteArray("01010101010101010101010101010101");
        byte[] secret =
                ArrayConverter.hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEFC0FEDEAD");
        HMAC hmac = new HMAC(MacAlgorithm.HMAC_SHA1);
        hmac.init(secret, data);
        hmac.compute();
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray("740b1374aac883ec9171730684b9f7bf84c56cc1"),
                hmac.getHmac());
    }

    @Test
    public void testComputeSHA256() throws NoSuchAlgorithmException {
        byte[] data = ArrayConverter.hexStringToByteArray("01010101010101010101010101010101");
        byte[] secret =
                ArrayConverter.hexStringToByteArray("DEADBEEFC0FFEEDEADBEEFC0FFEEDEADBEEFC0FFEEDEADBEEFC0FFEEDEAD");
        HMAC hmac = new HMAC(MacAlgorithm.HMAC_SHA256);
        hmac.init(secret, data);
        hmac.compute();
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray("13a357f844edb87c55437652e0be902e4f0a206783ee2ebda94effc27f3fc8f0"),
                hmac.getHmac());
    }

    @Test
    public void testComputeSHA384() throws NoSuchAlgorithmException {
        byte[] data = ArrayConverter.hexStringToByteArray("01010101010101010101010101010101");
        byte[] secret =
                ArrayConverter.hexStringToByteArray("DEADBEEFC0FFEEDEADBEEFC0FFEEDEADBEEFC0FFEEDEADBEEFC0FFEEDEAD");
        HMAC hmac = new HMAC(MacAlgorithm.HMAC_SHA384);
        hmac.init(secret, data);
        hmac.compute();
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray(
                        "d8ffb50c5c60a544d63c03c43410f571a61dce396ac51c3315d8ede2a2fe635cd2a67d761ec9c687b0831a5524f57f26"),
                hmac.getHmac());
    }

    @Test
    public void testComputeGOSTR3411() throws NoSuchAlgorithmException {
        byte[] data = ArrayConverter.hexStringToByteArray("01010101010101010101010101010101");
        byte[] secret =
                ArrayConverter.hexStringToByteArray("DEADBEEFC0FFEEDEADBEEFC0FFEEDEADBEEFC0FFEEDEADBEEFC0FFEEDEAD");
        HMAC hmac = new HMAC(MacAlgorithm.HMAC_GOSTR3411);
        hmac.init(secret, data);
        hmac.compute();
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray("655E2EC6E6E3E1FA11BEB5D854988634153CEB9EB0A21EA222528FE818B106D0"),
                hmac.getHmac());
    }

    @Test
    public void testComputeGOSTR3411_2012_256() throws NoSuchAlgorithmException {
        byte[] data = ArrayConverter.hexStringToByteArray("01010101010101010101010101010101");
        byte[] secret =
                ArrayConverter.hexStringToByteArray("DEADBEEFC0FFEEDEADBEEFC0FFEEDEADBEEFC0FFEEDEADBEEFC0FFEEDEAD");
        HMAC hmac = new HMAC(MacAlgorithm.HMAC_GOSTR3411_2012_256);
        hmac.init(secret, data);
        hmac.compute();
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray("44C2DEF1D9D4D4B98D0388735927C50B9FAFFB2B72D3D71E33DCA1CBF1A908D7"),
                hmac.getHmac());
    }
}