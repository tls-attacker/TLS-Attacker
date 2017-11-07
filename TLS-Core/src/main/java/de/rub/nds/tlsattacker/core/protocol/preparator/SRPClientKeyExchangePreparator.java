/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.constants.PRFAlgorithm;
import de.rub.nds.tlsattacker.core.crypto.PseudoRandomFunction;
import de.rub.nds.tlsattacker.core.protocol.message.SRPClientKeyExchangeMessage;
import static de.rub.nds.tlsattacker.core.protocol.preparator.Preparator.LOGGER;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import org.bouncycastle.util.BigIntegers;

/**
 *
 * @author Florian Linsner - florian.linsner@rub.de
 */
public class SRPClientKeyExchangePreparator extends ClientKeyExchangePreparator<SRPClientKeyExchangeMessage> {

    private BigInteger clientPublicKey;
    private byte[] premasterSecret;
    private byte[] random;
    private final SRPClientKeyExchangeMessage msg;

    public SRPClientKeyExchangePreparator(Chooser chooser, SRPClientKeyExchangeMessage msg) {
        super(chooser, msg);
        this.msg = msg;
    }

    @Override
    public void prepareHandshakeMessageContents() {
        LOGGER.debug("Preparing SRPClientExchangeMessage");
        msg.prepareComputations();
        setComputationGenerator(msg);
        setComputationModulus(msg);
        setComputationPrivateKey(msg);
        setComputationServerPublicKey(msg);
        setComputationSalt(msg);

        setSRPIdentity(msg);
        setSRPPassword(msg);

        clientPublicKey = calculatePublicKey(msg.getComputations().getGenerator().getValue(), msg.getComputations()
                .getModulus().getValue(), msg.getComputations().getPrivateKey().getValue());
        prepareModulus(msg);
        prepareModulusLength(msg);
        prepareGenerator(msg);
        prepareGeneratorLength(msg);
        prepareSalt(msg);
        prepareSaltLength(msg);
        preparePublicKey(msg);
        preparePublicKeyLength(msg);
        premasterSecret = calculatePremasterSecret(msg.getComputations().getModulus().getValue(), msg.getComputations()
                .getGenerator().getValue(), msg.getComputations().getPrivateKey().getValue(), msg.getComputations()
                .getServerPublicKey().getValue(), clientPublicKey, msg.getComputations().getSalt().getValue(), msg
                .getComputations().getSRPIdentity().getValue(), msg.getComputations().getSRPPassword().getValue());
        preparePremasterSecret(msg);
        prepareClientRandom(msg);
    }

    private BigInteger calculatePublicKey(BigInteger generator, BigInteger modulus, BigInteger privateKey) {
        return generator.modPow(privateKey, modulus);
    }

    private byte[] calculatePremasterSecret(BigInteger modulus, BigInteger generator, BigInteger privateKey,
            BigInteger serverPublicKey, BigInteger clientPublicKey, byte[] salt, byte[] identity, byte[] password) {
        BigInteger u = calculateU(clientPublicKey, serverPublicKey, modulus);
        BigInteger k = calculateSRP6Multiplier(modulus, generator);
        BigInteger x = calculateX(salt, identity, password);
        BigInteger helpValue1 = generator.modPow(x, modulus);
        BigInteger helpValue2 = k.multiply(helpValue1);
        helpValue2.mod(modulus);
        helpValue1 = serverPublicKey.subtract(helpValue2);
        helpValue1.mod(modulus);
        helpValue2 = u.multiply(x);
        helpValue2.mod(modulus);
        BigInteger helpValue3 = privateKey.add(helpValue2);
        helpValue3.mod(modulus);
        helpValue2 = helpValue1.modPow(helpValue3, modulus);
        byte[] output = ArrayConverter.bigIntegerToByteArray(helpValue2);
        return output;
    }

    private byte[] calculatePremasterSecretServer(BigInteger modulus, BigInteger generator,
            BigInteger serverPrivateKey, BigInteger serverPublicKey, BigInteger clientPublicKey, byte[] salt,
            byte[] identity, byte[] password) {
        BigInteger u = calculateU(clientPublicKey, serverPublicKey, modulus);
        BigInteger x = calculateX(salt, identity, password);
        BigInteger v = calculateV(x, generator, modulus);
        BigInteger helpValue1 = v.modPow(u, modulus);
        BigInteger helpValue2 = clientPublicKey.multiply(helpValue1);
        helpValue1 = helpValue2.modPow(serverPrivateKey, helpValue2);
        byte[] output = ArrayConverter.bigIntegerToByteArray(helpValue1);
        return output;
    }

    private BigInteger calculateV(BigInteger x, BigInteger generator, BigInteger modulus) {
        BigInteger v = generator.modPow(x, modulus);
        return v;
    }

    private BigInteger calculateU(BigInteger clientPublic, BigInteger serverPublic, BigInteger modulus) {
        byte[] paddedClientPublic = calculatePadding(modulus, clientPublic);
        LOGGER.debug("ClientPublic Key:"
                + ArrayConverter.bytesToHexString(ArrayConverter.bigIntegerToByteArray(clientPublic)));
        LOGGER.debug("PaddedClientPublic. " + ArrayConverter.bytesToHexString(paddedClientPublic));
        byte[] paddedServerPublic = calculatePadding(modulus, serverPublic);
        LOGGER.debug("ServerPublic Key:"
                + ArrayConverter.bytesToHexString(ArrayConverter.bigIntegerToByteArray(serverPublic)));
        LOGGER.debug("PaddedServerPublic. " + ArrayConverter.bytesToHexString(paddedServerPublic));
        byte[] hashInput = ArrayConverter.concatenate(paddedClientPublic, paddedServerPublic);
        LOGGER.debug("HashInput for u: " + ArrayConverter.bytesToHexString(hashInput));
        byte[] hashOutput = SHAsum(hashInput);
        LOGGER.debug("Hashvalue for u: " + ArrayConverter.bytesToHexString(hashOutput));
        BigInteger output = new BigInteger(1, hashOutput);
        return output;
    }

    private byte[] calculatePadding(BigInteger modulus, BigInteger topad) {
        byte[] padding;
        int modulusByteLength = ArrayConverter.bigIntegerToByteArray(modulus).length;
        byte[] paddingArray = ArrayConverter.bigIntegerToByteArray(topad);
        if (modulusByteLength == paddingArray.length) {
            return paddingArray;
        }
        int paddingByteLength = modulusByteLength - paddingArray.length;
        padding = new byte[paddingByteLength];
        byte[] output = ArrayConverter.concatenate(padding, paddingArray);
        return output;
    }

    public BigInteger calculateX(byte[] salt, byte[] identity, byte[] password) {
        byte[] hashInput1 = ArrayConverter.concatenate(identity, ArrayConverter.hexStringToByteArray("3A"), password);
        LOGGER.debug("HashInput for hashInput1: " + ArrayConverter.bytesToHexString(hashInput1));
        byte[] hashOutput1 = SHAsum(hashInput1);
        LOGGER.debug("Hashvalue for hashInput1: " + ArrayConverter.bytesToHexString(hashOutput1));
        byte[] hashInput2 = ArrayConverter.concatenate(salt, hashOutput1);
        LOGGER.debug("HashInput for hashInput2: " + ArrayConverter.bytesToHexString(hashInput2));
        byte[] hashOutput2 = SHAsum(hashInput2);
        LOGGER.debug("Hashvalue for hashInput2: " + ArrayConverter.bytesToHexString(hashOutput2));
        BigInteger output = new BigInteger(1, hashOutput2);
        return output;
    }

    private BigInteger calculateSRP6Multiplier(BigInteger modulus, BigInteger generator) {
        BigInteger srp6Multiplier;
        byte[] paddedGenerator = calculatePadding(modulus, generator);
        byte[] hashInput = ArrayConverter.concatenate(ArrayConverter.bigIntegerToByteArray(modulus), paddedGenerator);
        LOGGER.debug("HashInput SRP6Multi: " + ArrayConverter.bytesToHexString(hashInput));
        byte[] hashOutput = SHAsum(hashInput);
        srp6Multiplier = new BigInteger(1, hashOutput);
        return srp6Multiplier;
    }

    public byte[] SHAsum(byte[] toHash) {
        MessageDigest dig = null;
        try {
            dig = MessageDigest.getInstance("SHA-1");
        } catch (NoSuchAlgorithmException ex) {
            ex.printStackTrace();
        }
        dig.update(toHash);
        byte[] hashword = dig.digest();
        return hashword;
    }

    private void setComputationGenerator(SRPClientKeyExchangeMessage msg) {
        msg.getComputations().setGenerator(chooser.getSRPGenerator());
        LOGGER.debug("Generator: " + msg.getComputations().getGenerator().getValue());
    }

    private void setComputationModulus(SRPClientKeyExchangeMessage msg) {
        msg.getComputations().setModulus(chooser.getSRPModulus());
        LOGGER.debug("Modulus: " + msg.getComputations().getModulus().getValue());
    }

    private void preparePremasterSecret(SRPClientKeyExchangeMessage msg) {
        msg.getComputations().setPremasterSecret(premasterSecret);
        premasterSecret = msg.getComputations().getPremasterSecret().getValue();
        LOGGER.debug("PremasterSecret: "
                + ArrayConverter.bytesToHexString(msg.getComputations().getPremasterSecret().getValue()));
    }

    private void preparePublicKey(SRPClientKeyExchangeMessage msg) {
        msg.setPublicKey(clientPublicKey.toByteArray());
        LOGGER.debug("PublicKey: " + ArrayConverter.bytesToHexString(msg.getPublicKey().getValue()));
    }

    private void preparePublicKeyLength(SRPClientKeyExchangeMessage msg) {
        msg.setPublicKeyLength(msg.getPublicKey().getValue().length);
        LOGGER.debug("PublicKeyLength: " + msg.getPublicKeyLength().getValue());
    }

    private void prepareClientRandom(SRPClientKeyExchangeMessage msg) {
        random = ArrayConverter.concatenate(chooser.getClientRandom(), chooser.getServerRandom());
        msg.getComputations().setClientRandom(random);
        random = msg.getComputations().getClientRandom().getValue();
        LOGGER.debug("ClientRandom: "
                + ArrayConverter.bytesToHexString(msg.getComputations().getClientRandom().getValue()));
    }

    @Override
    public void prepareAfterParse() {
        BigInteger privateKey = chooser.getSRPServerPrivateKey();
        BigInteger clientPublic = new BigInteger(1, msg.getPublicKey().getValue());
        msg.prepareComputations();
        premasterSecret = calculatePremasterSecretServer(chooser.getSRPModulus(), chooser.getSRPGenerator(),
                privateKey, chooser.getSRPServerPublicKey(), clientPublic, chooser.getSRPSalt(),
                chooser.getSRPIdentity(), chooser.getSRPPassword());
        preparePremasterSecret(msg);
        prepareClientRandom(msg);
    }

    private void setComputationPrivateKey(SRPClientKeyExchangeMessage msg) {
        msg.getComputations().setPrivateKey(chooser.getSRPClientPrivateKey());
        LOGGER.debug("Computation PrivateKey: " + msg.getComputations().getPrivateKey().getValue().toString());
    }

    private void setComputationServerPublicKey(SRPClientKeyExchangeMessage msg) {
        msg.getComputations().setServerPublicKey(chooser.getSRPServerPublicKey());
        LOGGER.debug("Computation PublicKey: " + msg.getComputations().getServerPublicKey().getValue().toString());
    }

    private void prepareSalt(SRPClientKeyExchangeMessage msg) {
        msg.setSalt(msg.getComputations().getSalt());
        LOGGER.debug("Salt: " + ArrayConverter.bytesToHexString(msg.getSalt().getValue()));
    }

    private void prepareSaltLength(SRPClientKeyExchangeMessage msg) {
        msg.setSaltLength(msg.getSalt().getValue().length);
        LOGGER.debug("Salt Length: " + msg.getSaltLength().getValue());
    }

    private void setSRPIdentity(SRPClientKeyExchangeMessage msg) {
        msg.getComputations().setSRPIdentity(chooser.getSRPIdentity());
        LOGGER.debug("SRP Identity used for Computations: " + msg.getComputations().getSRPIdentity());
    }

    private void setSRPPassword(SRPClientKeyExchangeMessage msg) {
        msg.getComputations().setSRPPassword(chooser.getSRPPassword());
        LOGGER.debug("SRP Password used for Computations: " + msg.getComputations().getSRPPassword());
    }

    private void setComputationSalt(SRPClientKeyExchangeMessage msg) {
        msg.getComputations().setSalt(chooser.getSRPSalt());
        LOGGER.debug("Salt used for Computations: " + msg.getComputations().getSalt());
    }

    private void prepareGenerator(SRPClientKeyExchangeMessage msg) {
        msg.setGenerator(msg.getComputations().getGenerator().getByteArray());
        LOGGER.debug("Generator: " + ArrayConverter.bytesToHexString(msg.getGenerator().getValue()));
    }

    private void prepareModulus(SRPClientKeyExchangeMessage msg) {
        msg.setModulus(msg.getComputations().getModulus().getByteArray());
        LOGGER.debug("Modulus: " + ArrayConverter.bytesToHexString(msg.getModulus().getValue()));
    }

    private void prepareGeneratorLength(SRPClientKeyExchangeMessage msg) {
        msg.setGeneratorLength(msg.getGenerator().getValue().length);
        LOGGER.debug("Generator Length: " + msg.getGeneratorLength().getValue());
    }

    private void prepareModulusLength(SRPClientKeyExchangeMessage msg) {
        msg.setModulusLength(msg.getModulus().getValue().length);
        LOGGER.debug("Modulus Length: " + msg.getModulusLength().getValue());
    }
}
