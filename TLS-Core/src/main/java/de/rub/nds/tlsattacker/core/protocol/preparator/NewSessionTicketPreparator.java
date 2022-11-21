/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
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
        Config config = chooser.getConfig();
        SessionTicket newTicket = msg.getTicket();
        newTicket.setKeyName(config.getSessionTicketKeyName());

        CipherAlgorithm cipherAlgorithm = config.getSessionTicketCipherAlgorithm();
        byte[] encryptionKey = config.getSessionTicketEncryptionKey();

        byte[] iv = new byte[cipherAlgorithm.getBlocksize()];
        RandomHelper.getRandom().nextBytes(iv);
        newTicket.setIV(iv);

        StatePlaintext plainState = new StatePlaintext();
        plainState.generateStatePlaintext(chooser);
        StatePlaintextSerializer plaintextSerializer = new StatePlaintextSerializer(plainState);
        byte[] plainStateSerialized = plaintextSerializer.serialize();
        byte[] encryptedState;
        try {
            encryptedState = StaticTicketCrypto.encrypt(cipherAlgorithm, plainStateSerialized, encryptionKey,
                newTicket.getIV().getValue());
        } catch (CryptoException e) {
            LOGGER.warn("Could not encrypt SessionState. Using empty byte[]");
            LOGGER.debug(e);
            encryptedState = new byte[0];
        }
        newTicket.setEncryptedState(encryptedState);

        byte[] keyHMAC = config.getSessionTicketKeyHMAC();
        // Mac(Name + IV + TicketLength + Ticket)
        byte[] macInput = ArrayConverter.concatenate(config.getSessionTicketKeyName(), iv,
            ArrayConverter.intToBytes(encryptedState.length, HandshakeByteLength.ENCRYPTED_STATE_LENGTH),
            encryptedState);
        byte[] hmac;
        try {
            hmac = StaticTicketCrypto.generateHMAC(config.getSessionTicketMacAlgorithm(), macInput, keyHMAC);
        } catch (CryptoException ex) {
            LOGGER.warn("Could generate HMAC. Using empty byte[]");
            LOGGER.debug(ex);
            hmac = new byte[0];
        }
        newTicket.setMAC(hmac);

        newTicket.setEncryptedStateLength(encryptedState.length);
        SessionTicketSerializer sessionTicketSerializer = new SessionTicketSerializer(newTicket);
        byte[] sessionTicketSerialized = sessionTicketSerializer.serialize();
        msg.getTicket().setIdentityLength(sessionTicketSerialized.length);
        msg.getTicket().setIdentity(sessionTicketSerialized);
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

    private void prepareTicketTls13(NewSessionTicketMessage msg) {
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
