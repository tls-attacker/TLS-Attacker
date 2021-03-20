/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.preparator;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.modifiablevariable.util.RandomHelper;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherAlgorithm;
import de.rub.nds.tlsattacker.core.constants.ClientAuthenticationType;
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.constants.MacAlgorithm;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.protocol.message.NewSessionTicketMessage;
import de.rub.nds.tlsattacker.core.state.SessionTicket;
import de.rub.nds.tlsattacker.core.state.StatePlaintext;
import de.rub.nds.tlsattacker.core.state.serializer.SessionTicketSerializer;
import de.rub.nds.tlsattacker.core.state.serializer.StatePlaintextSerializer;
import de.rub.nds.tlsattacker.core.util.StaticTicketCrypto;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import de.rub.nds.tlsattacker.util.TimeHelper;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class NewSessionTicketPreparator extends HandshakeMessagePreparator<NewSessionTicketMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final NewSessionTicketMessage msg;

    public NewSessionTicketPreparator(Chooser chooser, NewSessionTicketMessage message) {
        super(chooser, message);
        this.msg = message;
    }

    private long generateTicketLifetimeHint() {
        long ticketLifeTimeHint = chooser.getConfig().getSessionTicketLifetimeHint();
        return ticketLifeTimeHint;
    }

    private void prepareTicketLifetimeHint(NewSessionTicketMessage msg) {
        msg.setTicketLifetimeHint(generateTicketLifetimeHint());
        LOGGER.debug("TicketLifetimeHint: " + msg.getTicketLifetimeHint().getValue());
    }

    private void prepareTicket(NewSessionTicketMessage msg) {
        Config cfg = chooser.getConfig();
        msg.prepareTicket();
        SessionTicket newTicket = msg.getTicket();
        newTicket.setKeyName(cfg.getSessionTicketKeyName());

        byte[] keyAES = cfg.getSessionTicketKeyAES();

        byte[] iv = new byte[16];
        RandomHelper.getRandom().nextBytes(iv);
        newTicket.setIV(iv);

        StatePlaintext plainState = generateStatePlaintext();
        StatePlaintextSerializer plaintextSerializer = new StatePlaintextSerializer(plainState);
        byte[] plainStateSerialized = plaintextSerializer.serialize();
        byte[] encryptedState;
        try {
            encryptedState = StaticTicketCrypto.encrypt(CipherAlgorithm.AES_128_CBC, plainStateSerialized, keyAES,
                newTicket.getIV().getValue());
        } catch (CryptoException e) {
            LOGGER.warn("Could not encrypt SessionState. Using empty byte[]");
            LOGGER.debug(e);
            encryptedState = new byte[0];
        }
        newTicket.setEncryptedState(encryptedState);

        byte[] keyHMAC = cfg.getSessionTicketKeyHMAC();
        // Mac(Name + IV + TicketLength + Ticket)
        byte[] macInput = ArrayConverter.concatenate(cfg.getSessionTicketKeyName(), iv,
            ArrayConverter.intToBytes(encryptedState.length, HandshakeByteLength.ENCRYPTED_STATE_LENGTH),
            encryptedState);
        byte[] hmac;
        try {
            hmac = StaticTicketCrypto.generateHMAC(MacAlgorithm.HMAC_SHA256, macInput, keyHMAC);
        } catch (CryptoException ex) {
            LOGGER.warn("Could generate HMAC. Using empty byte[]");
            LOGGER.debug(ex);
            hmac = new byte[0];
        }
        newTicket.setMAC(hmac);

        SessionTicketSerializer sessionTicketSerializer = new SessionTicketSerializer(newTicket);
        byte[] sessionTicketSerialized = sessionTicketSerializer.serialize();
        msg.setTicketLength(sessionTicketSerialized.length);
        LOGGER.debug("Ticket: " + msg.getTicket().toString());
    }

    @Override
    protected void prepareHandshakeMessageContents() {
        LOGGER.debug("Preparing NewSessionTicketMessage");
        prepareTicketLifetimeHint(msg);
        if (chooser.getSelectedProtocolVersion().isTLS13()) {
            prepareTicketTls13(msg);
        } else {
            prepareTicket(msg);
        }

    }

    /**
     * Generates the StatePlaintext for the SessionTicket, maybe put this as static function in the StatePlaintext class
     * for better testing/debugging
     *
     * @return A struct with State information defined in https://tools.ietf.org/html/rfc5077#section-4
     */
    private StatePlaintext generateStatePlaintext() {
        StatePlaintext plainState = new StatePlaintext();
        plainState.setCipherSuite(chooser.getSelectedCipherSuite().getValue());
        plainState.setCompressionMethod(chooser.getSelectedCompressionMethod().getValue());
        plainState.setMasterSecret(chooser.getMasterSecret());
        plainState.setProtocolVersion(chooser.getSelectedProtocolVersion().getValue());

        long timestamp = TimeHelper.getTime() / 1000;
        plainState.setTimestamp(timestamp);

        switch (chooser.getConfig().getClientAuthenticationType()) {
            case ANONYMOUS:
                plainState.setClientAuthenticationType(ClientAuthenticationType.ANONYMOUS.getValue());
                plainState.setClientAuthenticationData(new byte[0]);
                plainState.setClientAuthenticationDataLength(0);
                break;
            case CERTIFICATE_BASED:
                throw new UnsupportedOperationException("Certificate based ClientAuthentication is not supported");
            case PSK:
                throw new UnsupportedOperationException("PSK ClientAuthentication is not supported");
            default:
                throw new UnsupportedOperationException("Unknown ClientAuthenticationType");
        }

        return plainState;
    }

    private void prepareTicketTls13(NewSessionTicketMessage msg) {
        msg.prepareTicket();
        prepareTicketAgeAdd(msg);
        prepareNonce(msg);
        prepareIdentity(msg);
        prepareExtensions();
        prepareExtensionLength();
    }

    private void prepareTicketAgeAdd(NewSessionTicketMessage msg) {
        msg.getTicket().setTicketAgeAdd(chooser.getConfig().getDefaultSessionTicketAgeAdd());
    }

    private void prepareIdentity(NewSessionTicketMessage msg) {
        msg.getTicket().setIdentity(chooser.getConfig().getDefaultSessionTicketIdentity());
        msg.getTicket().setIdentityLength(msg.getTicket().getIdentity().getValue().length);
    }

    private void prepareNonce(NewSessionTicketMessage msg) {
        msg.getTicket().setTicketNonce(chooser.getConfig().getDefaultSessionTicketNonce());
        msg.getTicket().setTicketNonceLength(msg.getTicket().getTicketNonce().getValue().length);
    }
}
