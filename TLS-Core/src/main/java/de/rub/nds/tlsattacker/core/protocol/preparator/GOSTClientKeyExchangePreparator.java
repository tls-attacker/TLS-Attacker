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
import java.security.InvalidKeyException;
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
import org.bouncycastle.openssl.PEMException;
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
            msg.prepareComputations();
            if (is2001() || is2012()) {
                prepareUkm();

                String algorithm = is2012() ? "ECGOST3410-2012-256" : "ECGOST3410";
                KeyAgreement keyAgreement = KeyAgreement.getInstance(algorithm);

                if (clientMode) {
                    clientEcVko(keyAgreement);
                } else {
                    serverEcVko(keyAgreement);
                }
            } else {
                throw new WorkflowExecutionException("Unsupported cipher suite: " + chooser.getSelectedCipherSuite() + "!");
            }
        } catch (CryptoException | GeneralSecurityException | IOException e) {
            throw new WorkflowExecutionException("Could not prepare the key agreement!", e);
        }
    }

    private void clientEcVko(KeyAgreement keyAgreement) throws GeneralSecurityException, IOException {
        LOGGER.debug("Preparing client ECVKO.");
        preparePms();

        SubjectPublicKeyInfo ephemeralKey = null;
        if (canUseClientCert()) {
            LOGGER.debug("Using private key belonging to the client certificate.");
            init(keyAgreement, getClientPrivateKey());
        } else {
            LOGGER.debug("Using an ephemeral key.");
            KeyPair keyPair = generateEphemeralKey();
            init(keyAgreement, keyPair.getPrivate());

            ephemeralKey = SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded());
        }

        keyAgreement.doPhase(getServerPublicKey(), true);
        byte[] kek = keyAgreement.generateSecret();
        byte[] wrapped = wrap(true, kek, msg.getComputations().getPremasterSecret().getValue());
        prepareKeyBlob(ephemeralKey, wrapped);
    }

    private void init(KeyAgreement keyAgreement, PrivateKey key) throws GeneralSecurityException {
        UserKeyingMaterialSpec spec = new UserKeyingMaterialSpec(msg.getComputations().getUkm().getValue());
        keyAgreement.init(key, spec);
    }

    private boolean canUseClientCert() throws InvalidKeyException {
        return chooser.getContext().getClientCertificate() != null
                && equalSpecs();
    }

    private boolean equalSpecs() throws InvalidKeyException {
        return ((ECKey) getServerPublicKey()).getParameters()
                .equals(((ECKey) getClientPublicKey()).getParameters());
    }

    private KeyPair generateEphemeralKey() throws GeneralSecurityException {
        if (equalSpecs()) {
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

    private void serverEcVko(KeyAgreement keyAgreement) throws GeneralSecurityException, PEMException, CryptoException {
        LOGGER.debug("Preparing server ECVKO");
        TLSGostKeyTransportBlob transportBlob = TLSGostKeyTransportBlob
                .getInstance(msg.getKeyTransportBlob().getValue());
        LOGGER.debug("Preparing GOST key blob: " + ASN1Dump.dumpAsString(transportBlob, true));
        GostR3410KeyTransport keyBlob = transportBlob.getKeyBlob();
        if (!Arrays.equals(keyBlob.getTransportParameters().getUkm(),
                msg.getComputations().getUkm().getValue())) {
            throw new CryptoException("Client UKM != Server UKM");
        }

        init(keyAgreement, getServerPrivateKey());

        SubjectPublicKeyInfo ephemeralKey = keyBlob.getTransportParameters().getEphemeralPublicKey();
        if (ephemeralKey != null) {
            keyAgreement.doPhase(new JcaPEMKeyConverter().getPublicKey(ephemeralKey), true);
        } else {
            keyAgreement.doPhase(getClientPublicKey(), true);
        }

        byte[] wrapped = ArrayConverter.concatenate(keyBlob.getSessionEncryptedKey().getEncryptedKey(),
                keyBlob.getSessionEncryptedKey().getMacKey());
        byte[] pms = wrap(false, keyAgreement.generateSecret(), wrapped);
        msg.getComputations().setPremasterSecret(pms);
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

    private byte[] wrap(boolean wrap, byte[] kek, byte[] bytes) {
        LOGGER.debug("Using KEK: " + ArrayConverter.bytesToHexString(kek));

        byte[] sBox = is2012() ? GOST28147Cipher.SBox_Z : GOST28147Engine.getSBox("E-A");
        ParametersWithSBox withSBox = new ParametersWithSBox(new KeyParameter(kek), sBox);
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

    private void prepareKeyBlob(SubjectPublicKeyInfo ephemeralKey, byte[] wrapped) throws IOException {
        byte[] cek = new byte[32];
        byte[] mac = new byte[wrapped.length - cek.length];
        System.arraycopy(wrapped, 0, cek, 0, cek.length);
        System.arraycopy(wrapped, cek.length, mac, 0, mac.length);

        ASN1ObjectIdentifier params;
        if (is2012()) {
            params = RosstandartObjectIdentifiers.id_tc26_gost_28147_param_Z;
        } else {
            params = CryptoProObjectIdentifiers.id_Gost28147_89_CryptoPro_A_ParamSet;
        }

        GostR3410TransportParameters transportParameters = new GostR3410TransportParameters(params,
                ephemeralKey, msg.getComputations().getUkm().getValue());
        Gost2814789EncryptedKey encryptedKey = new Gost2814789EncryptedKey(cek, mac);
        GostR3410KeyTransport keyTransport = new GostR3410KeyTransport(encryptedKey, transportParameters);
        TLSGostKeyTransportBlob blob = new TLSGostKeyTransportBlob(keyTransport);
        msg.setKeyTransportBlob(blob.getEncoded());
        LOGGER.debug("Preparing GOST key blob: " + ASN1Dump.dumpAsString(blob, true));
    }

    private void prepareUkm() throws NoSuchAlgorithmException {
        byte[] random = ArrayConverter.concatenate(chooser.getClientRandom(), chooser.getServerRandom());
        msg.getComputations().setClientServerRandom(random);

        DigestAlgorithm digestAlgorithm = AlgorithmResolver
                .getDigestAlgorithm(chooser.getSelectedProtocolVersion(), chooser.getSelectedCipherSuite());
        MessageDigest digest = MessageDigest.getInstance(digestAlgorithm.getJavaName());
        byte[] hashedRandoms = digest.digest(msg.getComputations().getClientServerRandom().getValue());
        byte[] finalUkm = new byte[8];
        System.arraycopy(hashedRandoms, 0, finalUkm, 0, finalUkm.length);
        LOGGER.debug("Using GOST UKM: " + ArrayConverter.bytesToHexString(finalUkm));
        msg.getComputations().setUkm(finalUkm);
    }

    private PrivateKey getClientPrivateKey() throws InvalidKeyException {
        if (is2012()) {
            return chooser.getClientGost12PrivateKey();
        } else if (is2001()) {
            return chooser.getClientGost01PrivateKey();
        } else {
            throw new InvalidKeyException("Unsupported variant: " + exchangeAlg);
        }
    }

    private PrivateKey getServerPrivateKey() throws InvalidKeyException {
        if (is2012()) {
            return chooser.getServerGost12PrivateKey();
        } else if (is2001()) {
            return chooser.getServerGost01PrivateKey();
        } else {
            throw new InvalidKeyException("Unsupported variant: " + exchangeAlg);
        }
    }

    private PublicKey getClientPublicKey() throws InvalidKeyException {
        if (is2012()) {
            return chooser.getClientGost12PublicKey();
        } else if (is2001()) {
            return chooser.getClientGost01PublicKey();
        } else {
            throw new InvalidKeyException("Unsupported variant: " + exchangeAlg);
        }
    }

    private PublicKey getServerPublicKey() throws InvalidKeyException {
        if (is2012()) {
            return chooser.getServerGost12PublicKey();
        } else if (is2001()) {
            return chooser.getServerGost01PublicKey();
        } else {
            throw new InvalidKeyException("Unsupported variant: " + exchangeAlg);
        }
    }

    private boolean is2012() {
        return exchangeAlg == KeyExchangeAlgorithm.VKO_GOST12;
    }

    private boolean is2001() {
        return exchangeAlg == KeyExchangeAlgorithm.VKO_GOST01;
    }

}
