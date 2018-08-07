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
import de.rub.nds.tlsattacker.core.constants.KeyExchangeAlgorithm;
import de.rub.nds.tlsattacker.core.crypto.cipher.GOST28147Cipher;
import de.rub.nds.tlsattacker.core.crypto.gost.GOST28147WrapEngine;
import de.rub.nds.tlsattacker.core.crypto.gost.TLSGostKeyTransportBlob;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.protocol.message.GOSTClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import javax.crypto.KeyAgreement;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
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
import org.bouncycastle.jce.interfaces.ECKey;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

public class GOSTClientKeyExchangePreparator extends ClientKeyExchangePreparator<GOSTClientKeyExchangeMessage> {

    private final KeyExchangeAlgorithm exchangeAlg;
    private final GOSTClientKeyExchangeMessage msg;

    public GOSTClientKeyExchangePreparator(Chooser chooser, GOSTClientKeyExchangeMessage msg) {
        super(chooser, msg);
        this.msg = msg;

        exchangeAlg = AlgorithmResolver.getKeyExchangeAlgorithm(chooser.getSelectedCipherSuite());
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

                PrivateKey privateKey;
                SubjectPublicKeyInfo ephemeralKey = null;
                if (chooser.getContext().getClientCertificate() != null && areParamSpecsEqual()) {
                    LOGGER.debug("Using private key belonging to the used client certificate.");
                    privateKey = getClientPrivateKey();
                } else {
                    KeyPair keyPair = generateEphemeralKey();
                    privateKey = keyPair.getPrivate();

                    ephemeralKey = SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded());
                }

                prepareKek(privateKey, getServerPublicKey());

                prepareCek();
                prepareEncryptionParams();
                prepareKeyBlob(ephemeralKey);
            } else {
                TLSGostKeyTransportBlob transportBlob = TLSGostKeyTransportBlob
                        .getInstance(msg.getKeyTransportBlob().getValue());
                LOGGER.debug("Received GOST key blob: " + ASN1Dump.dumpAsString(transportBlob, true));

                GostR3410KeyTransport keyBlob = transportBlob.getKeyBlob();
                if (!Arrays.equals(keyBlob.getTransportParameters().getUkm(),
                        msg.getComputations().getUkm())) {
                    throw new CryptoException("Client UKM != Server UKM");
                }

                SubjectPublicKeyInfo ephemeralKey = keyBlob.getTransportParameters().getEphemeralPublicKey();
                PublicKey publicKey;
                if (ephemeralKey != null) {
                    publicKey = new JcaPEMKeyConverter().getPublicKey(ephemeralKey);
                } else {
                    publicKey = getClientPublicKey();
                }

                prepareKek(getServerPrivateKey(), publicKey);

                byte[] wrapped = ArrayConverter.concatenate(keyBlob.getSessionEncryptedKey().getEncryptedKey(),
                        keyBlob.getSessionEncryptedKey().getMacKey());

                byte[] pms = wrap(false, wrapped);
                msg.getComputations().setPremasterSecret(pms);
            }
        } catch (CryptoException | GeneralSecurityException | IOException e) {
            throw new WorkflowExecutionException("Could not prepare the key agreement!", e);
        }
    }

    private void prepareClientServerRandom() {
        byte[] random = ArrayConverter.concatenate(chooser.getClientRandom(), chooser.getServerRandom());
        msg.getComputations().setClientServerRandom(random);
        LOGGER.debug("ClientServerRandom: " + ArrayConverter.bytesToHexString(msg.getComputations().getClientServerRandom().getValue()));
    }

    private void prepareUkm() throws NoSuchAlgorithmException {
        DigestAlgorithm digestAlgorithm = AlgorithmResolver
                .getDigestAlgorithm(chooser.getSelectedProtocolVersion(), chooser.getSelectedCipherSuite());
        MessageDigest digest = MessageDigest.getInstance(digestAlgorithm.getJavaName());
        byte[] hash = digest.digest(msg.getComputations().getClientServerRandom().getValue());

        byte[] ukm = new byte[8];
        System.arraycopy(hash, 0, ukm, 0, ukm.length);
        msg.getComputations().setUkm(ukm);
        LOGGER.debug("UKM: " + ArrayConverter.bytesToHexString(msg.getComputations().getUkm()));
    }

    private void prepareKek(PrivateKey priv, PublicKey pub) throws GeneralSecurityException {
        String algorithm = is2012() ? "ECGOST3410-2012-256" : "ECGOST3410";
        KeyAgreement keyAgreement = KeyAgreement.getInstance(algorithm);
        keyAgreement.init(priv, new UserKeyingMaterialSpec(msg.getComputations().getUkm()));
        keyAgreement.doPhase(pub, true);

        byte[] kek = keyAgreement.generateSecret();
        msg.getComputations().setKek(kek);
        LOGGER.debug("KEK: " + ArrayConverter.bytesToHexString(msg.getComputations().getKek()));
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

    private KeyPair generateEphemeralKey() throws GeneralSecurityException {
        if (areParamSpecsEqual()) {
            LOGGER.debug("Using key from context.");
            return new KeyPair(getClientPublicKey(), getClientPrivateKey());
        } else {
            String algorithm = is2012() ? "ECGOST3410-2012" : "ECGOST3410";
            KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance(algorithm);

            ECNamedCurveSpec params = (ECNamedCurveSpec) ((java.security.interfaces.ECKey) getServerPublicKey()).getParams();
            LOGGER.debug("Generating " + algorithm + " key using curve " + params.getName());
            keyGenerator.initialize(params, chooser.getContext().getBadSecureRandom());
            return keyGenerator.generateKeyPair();
        }
    }

    private byte[] wrap(boolean wrap, byte[] bytes) {
        byte[] sBox = is2012() ? GOST28147Cipher.SBox_Z : GOST28147Engine.getSBox("E-A");
        KeyParameter keySpec = new KeyParameter(msg.getComputations().getKek());
        ParametersWithSBox withSBox = new ParametersWithSBox(keySpec, sBox);
        ParametersWithUKM withIV = new ParametersWithUKM(withSBox, msg.getComputations().getUkm());

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
        byte[] wrapped = wrap(true, msg.getComputations().getPremasterSecret().getValue());

        byte[] cek = new byte[32];
        System.arraycopy(wrapped, 0, cek, 0, cek.length);
        msg.getComputations().setCekEnc(cek);

        byte[] mac = new byte[wrapped.length - cek.length];
        System.arraycopy(wrapped, cek.length, mac, 0, mac.length);
        msg.getComputations().setCekMac(mac);
    }

    private void prepareEncryptionParams() {
        ASN1ObjectIdentifier encryptionParams;
        if (is2012()) {
            encryptionParams = RosstandartObjectIdentifiers.id_tc26_gost_28147_param_Z;
        } else {
            encryptionParams = CryptoProObjectIdentifiers.id_Gost28147_89_CryptoPro_A_ParamSet;
        }

        msg.getComputations().setEncryptionAlgOid(encryptionParams);
    }

    private void prepareKeyBlob(SubjectPublicKeyInfo ephemeralKey) throws IOException {
        Gost2814789EncryptedKey encryptedKey = new Gost2814789EncryptedKey(msg.getComputations().getCekEnc(),
                msg.getComputations().getCekMac());
        GostR3410TransportParameters params = new GostR3410TransportParameters(msg.getComputations().getEncryptionAlgOid(),
                ephemeralKey, msg.getComputations().getUkm());
        GostR3410KeyTransport transport = new GostR3410KeyTransport(encryptedKey, params);
        TLSGostKeyTransportBlob blob = new TLSGostKeyTransportBlob(transport);

        msg.setKeyTransportBlob(blob.getEncoded());
        LOGGER.debug("GOST key blob: " + ASN1Dump.dumpAsString(blob, true));
    }

    private boolean areParamSpecsEqual() {
        ECParameterSpec serverParams = ((ECKey) getServerPublicKey()).getParameters();
        ECParameterSpec clientParams = ((ECKey) getClientPublicKey()).getParameters();
        return serverParams.equals(clientParams);
    }

    private PrivateKey getClientPrivateKey() {
        if (is2012()) {
            return chooser.getClientGost12PrivateKey();
        } else if (is2001()) {
            return chooser.getClientGost01PrivateKey();
        } else {
            throw new WorkflowExecutionException("Unsupported variant: " + exchangeAlg);
        }
    }

    private PrivateKey getServerPrivateKey() {
        if (is2012()) {
            return chooser.getServerGost12PrivateKey();
        } else if (is2001()) {
            return chooser.getServerGost01PrivateKey();
        } else {
            throw new WorkflowExecutionException("Unsupported variant: " + exchangeAlg);
        }
    }

    private PublicKey getClientPublicKey() {
        if (is2012()) {
            return chooser.getClientGost12PublicKey();
        } else if (is2001()) {
            return chooser.getClientGost01PublicKey();
        } else {
            throw new WorkflowExecutionException("Unsupported variant: " + exchangeAlg);
        }
    }

    private PublicKey getServerPublicKey() {
        if (is2012()) {
            return chooser.getServerGost12PublicKey();
        } else if (is2001()) {
            return chooser.getServerGost01PublicKey();
        } else {
            throw new WorkflowExecutionException("Unsupported variant: " + exchangeAlg);
        }
    }

    private boolean is2012() {
        return exchangeAlg == KeyExchangeAlgorithm.VKO_GOST12;
    }

    private boolean is2001() {
        return exchangeAlg == KeyExchangeAlgorithm.VKO_GOST01;
    }

}
