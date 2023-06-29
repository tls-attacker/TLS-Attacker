/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.MacAlgorithm;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;

public class HMACTest {

    @Test
    public void testComputeMD5() throws NoSuchAlgorithmException {
        byte[] data =
                ArrayConverter.hexStringToByteArray(
                        "01010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101");
        byte[] secret =
                ArrayConverter.hexStringToByteArray(
                        "DEADBEEFC0FEDEADBEEFC0FEDEADBEEFC0FEDEADDEADBEEFC0FEDEADBEEFC0FEDEADBEEFC0FEDEADDEADBEEFC0FEDEADBEEFC0FEDEADBEEFC0FEDEADDEADBEEFC0FEDEADBEEFC0FEDEADBEEFC0FEDEADDEADBEEFC0FEDEADBEEFC0FEDEADBEEFC0FEDEAD");
        HMAC hmac = new HMAC(MacAlgorithm.HMAC_MD5);
        hmac.init(secret);
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray("9cf299c466fbe455d0b6dfe28d27f55f"),
                hmac.doFinal(data));
    }

    @Test
    public void testComputeSHA() throws NoSuchAlgorithmException {
        byte[] data = ArrayConverter.hexStringToByteArray("01010101010101010101010101010101");
        byte[] secret =
                ArrayConverter.hexStringToByteArray("DEADBEEFC0FEDEADBEEFC0FEDEADBEEFC0FEDEAD");
        HMAC hmac = new HMAC(MacAlgorithm.HMAC_SHA1);
        hmac.init(secret);
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray("740b1374aac883ec9171730684b9f7bf84c56cc1"),
                hmac.doFinal(data));
    }

    @Test
    public void testComputeSHA256() throws NoSuchAlgorithmException {
        byte[] data = ArrayConverter.hexStringToByteArray("01010101010101010101010101010101");
        byte[] secret =
                ArrayConverter.hexStringToByteArray(
                        "DEADBEEFC0FFEEDEADBEEFC0FFEEDEADBEEFC0FFEEDEADBEEFC0FFEEDEAD");
        HMAC hmac = new HMAC(MacAlgorithm.HMAC_SHA256);
        hmac.init(secret);
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray(
                        "13a357f844edb87c55437652e0be902e4f0a206783ee2ebda94effc27f3fc8f0"),
                hmac.doFinal(data));
    }

    @Test
    public void testComputeSHA384() throws NoSuchAlgorithmException {
        byte[] data = ArrayConverter.hexStringToByteArray("01010101010101010101010101010101");
        byte[] secret =
                ArrayConverter.hexStringToByteArray(
                        "DEADBEEFC0FFEEDEADBEEFC0FFEEDEADBEEFC0FFEEDEADBEEFC0FFEEDEAD");
        HMAC hmac = new HMAC(MacAlgorithm.HMAC_SHA384);
        hmac.init(secret);
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray(
                        "d8ffb50c5c60a544d63c03c43410f571a61dce396ac51c3315d8ede2a2fe635cd2a67d761ec9c687b0831a5524f57f26"),
                hmac.doFinal(data));
    }

    @Test
    public void testComputeGOSTR3411() throws NoSuchAlgorithmException {
        Security.addProvider(new BouncyCastleProvider());
        byte[] data = ArrayConverter.hexStringToByteArray("01010101010101010101010101010101");
        byte[] secret =
                ArrayConverter.hexStringToByteArray(
                        "DEADBEEFC0FFEEDEADBEEFC0FFEEDEADBEEFC0FFEEDEADBEEFC0FFEEDEAD");
        HMAC hmac = new HMAC(MacAlgorithm.HMAC_GOSTR3411);
        hmac.init(secret);
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray(
                        "655E2EC6E6E3E1FA11BEB5D854988634153CEB9EB0A21EA222528FE818B106D0"),
                hmac.doFinal(data));
    }

    @Test
    public void testComputeGOSTR3411_2012_256() throws NoSuchAlgorithmException {
        Security.addProvider(new BouncyCastleProvider());
        byte[] data = ArrayConverter.hexStringToByteArray("01010101010101010101010101010101");
        byte[] secret =
                ArrayConverter.hexStringToByteArray(
                        "DEADBEEFC0FFEEDEADBEEFC0FFEEDEADBEEFC0FFEEDEADBEEFC0FFEEDEAD");
        HMAC hmac = new HMAC(MacAlgorithm.HMAC_GOSTR3411_2012_256);
        hmac.init(secret);
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray(
                        "44C2DEF1D9D4D4B98D0388735927C50B9FAFFB2B72D3D71E33DCA1CBF1A908D7"),
                hmac.doFinal(data));
    }
}
