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
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.DigestAlgorithm;
import de.rub.nds.tlsattacker.core.constants.GOSTCurve;
import de.rub.nds.tlsattacker.core.crypto.ec.CustomECPoint;
import de.rub.nds.tlsattacker.core.crypto.gost.GOST28147WrapEngine;
import de.rub.nds.tlsattacker.core.crypto.gost.TLSGostKeyTransportBlob;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.protocol.message.GOSTClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.util.GOSTUtils;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import javax.crypto.KeyAgreement;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.cryptopro.Gost2814789EncryptedKey;
import org.bouncycastle.asn1.cryptopro.GostR3410KeyTransport;
import org.bouncycastle.asn1.cryptopro.GostR3410TransportParameters;
import org.bouncycastle.asn1.rosstandart.RosstandartObjectIdentifiers;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.engines.GOST28147Engine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithSBox;
import org.bouncycastle.crypto.params.ParametersWithUKM;
import org.bouncycastle.jcajce.spec.UserKeyingMaterialSpec;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

public abstract class GOSTClientKeyExchangePreparator extends ClientKeyExchangePreparator<GOSTClientKeyExchangeMessage> {

    private final static Logger LOGGER = LogManager.getLogger();

    private final GOSTClientKeyExchangeMessage msg;

    private static Map<ASN1ObjectIdentifier, String> oidMappings = new HashMap<>();

    static {
        oidMappings.put(CryptoProObjectIdentifiers.id_Gost28147_89_CryptoPro_TestParamSet, "E-TEST");
        oidMappings.put(CryptoProObjectIdentifiers.id_Gost28147_89_CryptoPro_A_ParamSet, "E-A");
        oidMappings.put(CryptoProObjectIdentifiers.id_Gost28147_89_CryptoPro_B_ParamSet, "E-B");
        oidMappings.put(CryptoProObjectIdentifiers.id_Gost28147_89_CryptoPro_C_ParamSet, "E-C");
        oidMappings.put(CryptoProObjectIdentifiers.id_Gost28147_89_CryptoPro_D_ParamSet, "E-D");
        oidMappings.put(RosstandartObjectIdentifiers.id_tc26_gost_28147_param_Z, "Param-Z");
    }

    public GOSTClientKeyExchangePreparator(Chooser chooser, GOSTClientKeyExchangeMessage msg) {
        super(chooser, msg);
        this.msg = msg;
    }

    @Override
    protected void prepareHandshakeMessageContents() {
        prepareAfterParse(true);
    }

    @Override
    public void prepareAfterParse(boolean clientMode) {
        try {
            LOGGER.debug("Preparing GOST EC VKO. Client mode: " + clientMode);

            msg.prepareComputations();
            prepareClientServerRandom();
            prepareUkm();

            if (clientMode) {
                preparePms();

                if (chooser.getContext().getClientCertificate() != null && areParamSpecsEqual()) {
                    LOGGER.debug("Using private key belonging to the used client certificate.");
                    msg.getComputations().setPrivateKey(getClientPrivateKey());
                } else {
                    prepareEphemeralKey();
                }

                prepareKek(msg.getComputations().getPrivateKey().getValue(), generatePublicKey(getServerPublicKey()));

                prepareEncryptionParams();
                prepareCek();
                prepareKeyBlob();
            } else {
                TLSGostKeyTransportBlob transportBlob = TLSGostKeyTransportBlob.getInstance(msg.getKeyTransportBlob()
                        .getValue());
                LOGGER.debug("Received GOST key blob: " + ASN1Dump.dumpAsString(transportBlob, true));

                GostR3410KeyTransport keyBlob = transportBlob.getKeyBlob();
                if (!Arrays
                        .equals(keyBlob.getTransportParameters().getUkm(), msg.getComputations().getUkm().getValue())) {
                    throw new CryptoException("Client UKM != Server UKM");
                }

                SubjectPublicKeyInfo ephemeralKey = keyBlob.getTransportParameters().getEphemeralPublicKey();
                PublicKey publicKey;
                if (ephemeralKey != null) {
                    publicKey = new JcaPEMKeyConverter().getPublicKey(ephemeralKey);
                } else {
                    publicKey = generatePublicKey(getClientPublicKey());
                }

                prepareKek(getServerPrivateKey(), publicKey);

                byte[] wrapped = ArrayConverter.concatenate(keyBlob.getSessionEncryptedKey().getEncryptedKey(), keyBlob
                        .getSessionEncryptedKey().getMacKey());

                String sBoxName = oidMappings.get(keyBlob.getTransportParameters().getEncryptionParamSet());
                byte[] pms = wrap(false, wrapped, sBoxName);
                msg.getComputations().setPremasterSecret(pms);
            }
        } catch (CryptoException | GeneralSecurityException | IOException e) {
            throw new WorkflowExecutionException("Could not prepare the key agreement!", e);
        }
    }

    private void prepareClientServerRandom() {
        byte[] random = ArrayConverter.concatenate(chooser.getClientRandom(), chooser.getServerRandom());
        msg.getComputations().setClientServerRandom(random);
        LOGGER.debug("ClientServerRandom: "
                + ArrayConverter.bytesToHexString(msg.getComputations().getClientServerRandom().getValue()));
    }

    private void prepareUkm() throws NoSuchAlgorithmException {
        DigestAlgorithm digestAlgorithm = AlgorithmResolver.getDigestAlgorithm(chooser.getSelectedProtocolVersion(),
                chooser.getSelectedCipherSuite());
        MessageDigest digest = MessageDigest.getInstance(digestAlgorithm.getJavaName());
        byte[] hash = digest.digest(msg.getComputations().getClientServerRandom().getValue());

        byte[] ukm = new byte[8];
        System.arraycopy(hash, 0, ukm, 0, ukm.length);
        msg.getComputations().setUkm(ukm);
        LOGGER.debug("UKM: " + ArrayConverter.bytesToHexString(msg.getComputations().getUkm()));
    }

    private void prepareKek(BigInteger priv, PublicKey pub) throws GeneralSecurityException {
        KeyAgreement keyAgreement = KeyAgreement.getInstance(getKeyAgreementAlgorithm());

        PrivateKey privateKey = generatePrivateKey(priv);

        keyAgreement.init(privateKey, new UserKeyingMaterialSpec(msg.getComputations().getUkm().getValue()));
        keyAgreement.doPhase(pub, true);

        byte[] kek = keyAgreement.generateSecret();
        msg.getComputations().setKeyEncryptionKey(kek);
        LOGGER.debug("KEK: " + ArrayConverter.bytesToHexString(msg.getComputations().getKeyEncryptionKey()));
    }

    private void preparePms() {
        byte[] pms = chooser.getContext().getPreMasterSecret();
        if (pms != null) {
            LOGGER.debug("Using preset PreMasterSecret from context.");
        } else {
            LOGGER.debug("Generating random PreMasterSecret.");
            pms = new byte[32];
            chooser.getContext().getRandom().nextBytes(pms);
        }

        msg.getComputations().setPremasterSecret(pms);
    }

    private void prepareEphemeralKey() throws GeneralSecurityException {
        if (areParamSpecsEqual()) {
            LOGGER.debug("Using key from context.");
            msg.getComputations().setPrivateKey(getClientPrivateKey());
            msg.getComputations().setClientPublicKey(getClientPublicKey());
        } else {
            KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance(getKeyPairGeneratorAlgorithm());
            ECNamedCurveSpec params = GOSTUtils.getEcParameterSpec(getServerCurve());

            LOGGER.debug("Generating key using curve " + params.getName());
            keyGenerator.initialize(params, chooser.getContext().getBadSecureRandom());
            KeyPair pair = keyGenerator.generateKeyPair();

            msg.getComputations().setPrivateKey(((ECPrivateKey) pair.getPrivate()).getS());
            msg.getComputations().setClientPublicKey(toCustomECPoint(((ECPublicKey) pair.getPublic())));
        }
    }

    private byte[] wrap(boolean wrap, byte[] bytes, String sBoxName) {
        byte[] sBox = GOST28147Engine.getSBox(sBoxName);
        KeyParameter keySpec = new KeyParameter(msg.getComputations().getKeyEncryptionKey().getValue());
        ParametersWithSBox withSBox = new ParametersWithSBox(keySpec, sBox);
        ParametersWithUKM withIV = new ParametersWithUKM(withSBox, msg.getComputations().getUkm().getValue());

        GOST28147WrapEngine cipher = new GOST28147WrapEngine();
        cipher.init(wrap, withIV);

        byte[] result;
        if (wrap) {
            LOGGER.debug("Wrapping GOST pms: " + ArrayConverter.bytesToHexString(bytes));
            result = cipher.wrap(bytes, 0, bytes.length);
        } else {
            LOGGER.debug("Unwrapping GOST pms: " + ArrayConverter.bytesToHexString(bytes));
            result = cipher.unwrap(bytes, 0, bytes.length);
        }
        LOGGER.debug("Wrap result: " + ArrayConverter.bytesToHexString(result));
        return result;
    }

    private void prepareCek() {
        ASN1ObjectIdentifier param = new ASN1ObjectIdentifier(msg.getComputations().getEncryptionParamSet().getValue());
        String sBoxName = oidMappings.get(param);
        byte[] wrapped = wrap(true, msg.getComputations().getPremasterSecret().getValue(), sBoxName);

        byte[] cek = new byte[32];
        System.arraycopy(wrapped, 0, cek, 0, cek.length);
        msg.getComputations().setEncryptedKey(cek);

        byte[] mac = new byte[wrapped.length - cek.length];
        System.arraycopy(wrapped, cek.length, mac, 0, mac.length);
        msg.getComputations().setMacKey(mac);
    }

    private void prepareEncryptionParams() {
        msg.getComputations().setEncryptionParamSet(getEncryptionParameters());
    }

    private void prepareKeyBlob() throws IOException {
        SubjectPublicKeyInfo ephemeralKey = null;
        CustomECPoint ecPoint = msg.getComputations().getClientPublicKey();
        if (ecPoint != null) {
            ephemeralKey = SubjectPublicKeyInfo.getInstance(generatePublicKey(ecPoint).getEncoded());
        }

        Gost2814789EncryptedKey encryptedKey = new Gost2814789EncryptedKey(msg.getComputations().getEncryptedKey()
                .getValue(), getMaskKey(), msg.getComputations().getMacKey().getValue());
        ASN1ObjectIdentifier paramSet = new ASN1ObjectIdentifier(msg.getComputations().getEncryptionParamSet()
                .getValue());
        GostR3410TransportParameters params = new GostR3410TransportParameters(paramSet, ephemeralKey, msg
                .getComputations().getUkm().getValue());
        GostR3410KeyTransport transport = new GostR3410KeyTransport(encryptedKey, params);
        DERSequence proxyKeyBlobs = (DERSequence) DERSequence.getInstance(getProxyKeyBlobs());
        TLSGostKeyTransportBlob blob = new TLSGostKeyTransportBlob(transport, proxyKeyBlobs);

        msg.setKeyTransportBlob(blob.getEncoded());
        LOGGER.debug("GOST key blob: " + ASN1Dump.dumpAsString(blob, true));
    }

    private byte[] getProxyKeyBlobs() {
        if (msg.getComputations().getProxyKeyBlobs() != null) {
            return msg.getComputations().getProxyKeyBlobs().getValue();
        } else {
            return null;
        }
    }

    private byte[] getMaskKey() {
        if (msg.getComputations().getMaskKey() != null) {
            return msg.getComputations().getMaskKey().getValue();
        } else {
            return null;
        }
    }

    private CustomECPoint toCustomECPoint(ECPublicKey key) {
        ECPoint q = key.getQ();
        return new CustomECPoint(q.getRawXCoord().toBigInteger(), q.getRawYCoord().toBigInteger());
    }

    protected abstract GOSTCurve getServerCurve();

    protected abstract ASN1ObjectIdentifier getEncryptionParameters();

    protected abstract boolean areParamSpecsEqual();

    protected abstract String getKeyAgreementAlgorithm();

    protected abstract String getKeyPairGeneratorAlgorithm();

    protected abstract PrivateKey generatePrivateKey(BigInteger s);

    protected abstract PublicKey generatePublicKey(CustomECPoint point);

    protected abstract BigInteger getClientPrivateKey();

    protected abstract CustomECPoint getClientPublicKey();

    protected abstract BigInteger getServerPrivateKey();

    protected abstract CustomECPoint getServerPublicKey();

}
