/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.preparator;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.protocol.message.SrpServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SrpServerKeyExchangePreparator
        extends ServerKeyExchangePreparator<SrpServerKeyExchangeMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private BigInteger publicKey;
    private SignatureAndHashAlgorithm selectedSignatureHashAlgo;
    private byte[] signature;
    private final SrpServerKeyExchangeMessage msg;

    public SrpServerKeyExchangePreparator(Chooser chooser, SrpServerKeyExchangeMessage message) {
        super(chooser, message);
        this.msg = message;
    }

    @Override
    public void prepareHandshakeMessageContents() {
        msg.prepareKeyExchangeComputations();
        setComputedModulus(msg);
        setComputedGenerator(msg);
        setComputedSalt(msg);
        setComputedPrivateKey(msg);
        setSRPIdentity(msg);
        setSRPPassword(msg);
        BigInteger modulus = msg.getKeyExchangeComputations().getModulus().getValue();
        BigInteger generator = msg.getKeyExchangeComputations().getGenerator().getValue();
        BigInteger privateKey = msg.getKeyExchangeComputations().getPrivateKey().getValue();
        byte[] identity = msg.getKeyExchangeComputations().getSRPIdentity().getValue();
        byte[] password = msg.getKeyExchangeComputations().getSRPPassword().getValue();
        byte[] salt = msg.getKeyExchangeComputations().getSalt().getValue();

        // Compute PublicKey
        publicKey = generatePublicKey(modulus, generator, privateKey, identity, password, salt);
        publicKey.mod(modulus);
        prepareModulus(msg);
        prepareModulusLength(msg);
        prepareGenerator(msg);
        prepareGeneratorLength(msg);
        prepareSalt(msg);
        prepareSaltLength(msg);
        preparePublicKey(msg);
        preparePublicKeyLength(msg);
        selectedSignatureHashAlgo = chooseSignatureAndHashAlgorithm();
        prepareSignatureAndHashAlgorithm(msg);
        prepareClientServerRandom(msg);
        signature = generateSignature(selectedSignatureHashAlgo, generateToBeSigned());

        prepareSignature(msg);
        prepareSignatureLength(msg);
    }

    private BigInteger generatePublicKey(
            BigInteger modulus,
            BigInteger generator,
            BigInteger privateKey,
            byte[] identity,
            byte[] password,
            byte[] salt) {
        BigInteger k = calculateSRP6Multiplier(modulus, generator);
        BigInteger x = calculateX(salt, identity, password);
        BigInteger v;
        if (modulus.compareTo(BigInteger.ZERO) >= 0) {
            v = generator.modPow(x, modulus);
        } else {
            LOGGER.warn("Modulus is zero or negative. Using publicKey=0.");
            return BigInteger.ZERO;
        }
        BigInteger helpValue1 = k.multiply(v);
        BigInteger helpValue2 = helpValue1.mod(modulus);
        helpValue1 = generator.modPow(privateKey, modulus);
        BigInteger helpValue3 = helpValue1.add(helpValue2);
        helpValue1 = helpValue3.mod(modulus);

        publicKey = helpValue1;

        LOGGER.debug(
                "Server-Public-Key: {}", () -> ArrayConverter.bigIntegerToByteArray(publicKey));
        return publicKey;
    }

    public BigInteger calculateX(byte[] salt, byte[] identity, byte[] password) {
        byte[] hashInput1 =
                ArrayConverter.concatenate(
                        identity, ArrayConverter.hexStringToByteArray("3A"), password);
        LOGGER.debug("HashInput for hashInput1: {}", hashInput1);
        byte[] hashOutput1 = shaSum(hashInput1);
        LOGGER.debug("HashValue for hashInput1: {}", hashOutput1);
        byte[] hashInput2 = ArrayConverter.concatenate(salt, hashOutput1);
        LOGGER.debug("HashInput for hashInput2: {}", hashInput2);
        byte[] hashOutput2 = shaSum(hashInput2);
        LOGGER.debug("HashValue for hashInput2: {}", hashOutput2);
        return new BigInteger(1, hashOutput2);
    }

    private BigInteger calculateSRP6Multiplier(BigInteger modulus, BigInteger generator) {
        byte[] paddedGenerator = calculatePadding(modulus, generator);
        byte[] hashInput =
                ArrayConverter.concatenate(
                        ArrayConverter.bigIntegerToByteArray(modulus), paddedGenerator);
        LOGGER.debug("HashInput SRP6Multi: {}", hashInput);
        byte[] hashOutput = shaSum(hashInput);
        return new BigInteger(1, hashOutput);
    }

    public byte[] shaSum(byte[] toHash) {
        MessageDigest dig = null;
        try {
            dig = MessageDigest.getInstance("SHA-1");
        } catch (NoSuchAlgorithmException ex) {
            throw new WorkflowExecutionException("Could not find SHA-1 Algorithm", ex);
        }
        dig.update(toHash);
        return dig.digest();
    }

    private byte[] calculatePadding(BigInteger modulus, BigInteger toPad) {
        byte[] padding;
        int modulusByteLength = ArrayConverter.bigIntegerToByteArray(modulus).length;
        byte[] paddingArray = ArrayConverter.bigIntegerToByteArray(toPad);
        if (modulusByteLength == paddingArray.length) {
            return paddingArray;
        }
        int paddingByteLength = modulusByteLength - paddingArray.length;
        if (paddingByteLength < 0) {
            LOGGER.warn("Padding ByteLength negative, Using Zero instead");
            paddingByteLength = 0;
        }
        padding = new byte[paddingByteLength];
        return ArrayConverter.concatenate(padding, paddingArray);
    }

    private byte[] generateToBeSigned() {
        byte[] srpParams =
                ArrayConverter.concatenate(
                        ArrayConverter.intToBytes(
                                msg.getModulusLength().getValue(),
                                HandshakeByteLength.SRP_MODULUS_LENGTH),
                        msg.getModulus().getValue(),
                        ArrayConverter.intToBytes(
                                msg.getGeneratorLength().getValue(),
                                HandshakeByteLength.SRP_GENERATOR_LENGTH),
                        msg.getGenerator().getValue(),
                        ArrayConverter.intToBytes(
                                msg.getSaltLength().getValue(),
                                HandshakeByteLength.SRP_SALT_LENGTH),
                        msg.getSalt().getValue(),
                        ArrayConverter.intToBytes(
                                msg.getPublicKeyLength().getValue(),
                                HandshakeByteLength.SRP_PUBLICKEY_LENGTH),
                        msg.getPublicKey().getValue());
        return ArrayConverter.concatenate(
                msg.getKeyExchangeComputations().getClientServerRandom().getValue(), srpParams);
    }

    private void prepareGenerator(SrpServerKeyExchangeMessage msg) {
        msg.setGenerator(msg.getKeyExchangeComputations().getGenerator().getByteArray());
        LOGGER.debug("Generator: {}", msg.getGenerator().getValue());
    }

    private void prepareModulus(SrpServerKeyExchangeMessage msg) {
        msg.setModulus(msg.getKeyExchangeComputations().getModulus().getByteArray());
        LOGGER.debug("Modulus: {}", msg.getModulus().getValue());
    }

    private void prepareGeneratorLength(SrpServerKeyExchangeMessage msg) {
        msg.setGeneratorLength(msg.getGenerator().getValue().length);
        LOGGER.debug("Generator Length: " + msg.getGeneratorLength().getValue());
    }

    private void prepareSalt(SrpServerKeyExchangeMessage msg) {
        msg.setSalt(msg.getKeyExchangeComputations().getSalt());
        LOGGER.debug("Salt: {}", msg.getSalt().getValue());
    }

    private void prepareSaltLength(SrpServerKeyExchangeMessage msg) {
        msg.setSaltLength(msg.getSalt().getValue().length);
        LOGGER.debug("Salt Length: " + msg.getSaltLength().getValue());
    }

    private void prepareModulusLength(SrpServerKeyExchangeMessage msg) {
        msg.setModulusLength(msg.getModulus().getValue().length);
        LOGGER.debug("Modulus Length: " + msg.getModulusLength().getValue());
    }

    private void preparePublicKey(SrpServerKeyExchangeMessage msg) {
        msg.setPublicKey(publicKey.toByteArray());
        LOGGER.debug("PublicKey: {}", msg.getPublicKey().getValue());
    }

    private void preparePublicKeyLength(SrpServerKeyExchangeMessage msg) {
        msg.setPublicKeyLength(msg.getPublicKey().getValue().length);
        LOGGER.debug("PublicKeyLength: {}", msg.getPublicKeyLength().getValue());
    }

    private void setComputedPrivateKey(SrpServerKeyExchangeMessage msg) {
        msg.getKeyExchangeComputations().setPrivateKey(chooser.getSRPServerPrivateKey());
        LOGGER.debug("PrivateKey: " + msg.getKeyExchangeComputations().getPrivateKey().getValue());
    }

    private void setComputedModulus(SrpServerKeyExchangeMessage msg) {
        msg.getKeyExchangeComputations().setModulus(chooser.getSRPModulus());
        LOGGER.debug(
                "Modulus used for Computations: 0x"
                        + msg.getKeyExchangeComputations().getModulus().getValue().toString(16));
    }

    private void setSRPIdentity(SrpServerKeyExchangeMessage msg) {
        msg.getKeyExchangeComputations().setSRPIdentity(chooser.getSRPIdentity());
        LOGGER.debug(
                "SRP Identity used for Computations: "
                        + msg.getKeyExchangeComputations().getSRPIdentity());
    }

    private void setSRPPassword(SrpServerKeyExchangeMessage msg) {
        msg.getKeyExchangeComputations().setSRPPassword(chooser.getSRPPassword());
        LOGGER.debug(
                "SRP Password used for Computations: "
                        + msg.getKeyExchangeComputations().getSRPPassword());
    }

    private void setComputedSalt(SrpServerKeyExchangeMessage msg) {
        msg.getKeyExchangeComputations().setSalt(chooser.getSRPServerSalt());
        LOGGER.debug("Salt used for Computations: " + msg.getKeyExchangeComputations().getSalt());
    }

    private void setComputedGenerator(SrpServerKeyExchangeMessage msg) {
        msg.getKeyExchangeComputations().setGenerator(chooser.getSRPGenerator());
        LOGGER.debug(
                "Generator used for Computations: 0x"
                        + msg.getKeyExchangeComputations().getGenerator().getValue().toString(16));
    }

    private void prepareSignatureAndHashAlgorithm(SrpServerKeyExchangeMessage msg) {
        msg.setSignatureAndHashAlgorithm(selectedSignatureHashAlgo.getByteValue());
        LOGGER.debug("SignatureAlgorithm: {}", msg.getSignatureAndHashAlgorithm().getValue());
    }

    private void prepareClientServerRandom(SrpServerKeyExchangeMessage msg) {
        msg.getKeyExchangeComputations()
                .setClientServerRandom(
                        ArrayConverter.concatenate(
                                chooser.getClientRandom(), chooser.getServerRandom()));
        LOGGER.debug(
                "ClientServerRandom: {}",
                ArrayConverter.bytesToHexString(
                        msg.getKeyExchangeComputations().getClientServerRandom().getValue()));
    }

    private void prepareSignature(SrpServerKeyExchangeMessage msg) {
        msg.setSignature(signature);
        LOGGER.debug("Signature: {}", msg.getSignature().getValue());
    }

    private void prepareSignatureLength(SrpServerKeyExchangeMessage msg) {
        msg.setSignatureLength(msg.getSignature().getValue().length);
        LOGGER.debug("SignatureLength: " + msg.getSignatureLength().getValue());
    }
}
