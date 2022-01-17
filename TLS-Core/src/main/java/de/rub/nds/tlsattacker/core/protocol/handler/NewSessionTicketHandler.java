/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.DigestAlgorithm;
import de.rub.nds.tlsattacker.core.constants.HKDFAlgorithm;
import de.rub.nds.tlsattacker.core.constants.Tls13KeySetType;
import de.rub.nds.tlsattacker.core.crypto.HKDFunction;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.protocol.message.NewSessionTicketMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.psk.PskSet;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.state.session.TicketSession;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.LinkedList;
import java.util.List;
import javax.crypto.Mac;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class NewSessionTicketHandler extends HandshakeMessageHandler<NewSessionTicketMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public NewSessionTicketHandler(TlsContext context) {
        super(context);
    }

    @Override
    public void adjustContext(NewSessionTicketMessage message) {
        if (context.getChooser().getSelectedProtocolVersion().isTLS13()) {
            adjustPskSets(message);
        } else {
            byte[] ticket = message.getTicket().getIdentity().getValue();
            LOGGER.debug("Adding Session for Ticket resumption using dummy SessionID");
            TicketSession session = new TicketSession(context.getChooser().getMasterSecret(), ticket);
            context.addNewSession(session);
        }
    }

    private void adjustPskSets(NewSessionTicketMessage message) {
        LOGGER.debug("Adjusting PSK-Sets");
        List<PskSet> pskSets = context.getPskSets();
        if (pskSets == null) {
            pskSets = new LinkedList<>();
        }
        PskSet pskSet = new PskSet();
        pskSet.setCipherSuite(context.getChooser().getSelectedCipherSuite());
        if (message.getTicket().getTicketAgeAdd() != null) {
            pskSet.setTicketAgeAdd(message.getTicket().getTicketAgeAdd().getValue());
        } else {
            LOGGER.warn("No TicketAge specified in SessionTicket");
        }
        if (message.getTicket().getIdentity() != null) {
            pskSet.setPreSharedKeyIdentity(message.getTicket().getIdentity().getValue());
        } else {
            LOGGER.warn("No Identity in ticket. Using new byte[0] instead");
            pskSet.setPreSharedKeyIdentity(new byte[0]);
        }
        pskSet.setTicketAge(getTicketAge());
        if (message.getTicket().getTicketNonce() != null) {
            pskSet.setTicketNonce(message.getTicket().getTicketNonce().getValue());
        } else {
            LOGGER.warn("No nonce in ticket. Using new byte[0] instead");
            pskSet.setTicketNonce(new byte[0]);
        }
        // only derive PSK if client finished was already sent, because full handshake transcript is required
        if (context.getActiveClientKeySetType() == Tls13KeySetType.APPLICATION_TRAFFIC_SECRETS) {
            pskSet.setPreSharedKey(derivePsk(pskSet));
        }

        LOGGER.debug("Adding PSK Set");
        pskSets.add(pskSet);
        context.setPskSets(pskSets);

    }

    private String getTicketAge() {
        DateTimeFormatter dateTimeFormatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS");
        LocalDateTime ticketDate = LocalDateTime.now();

        return ticketDate.format(dateTimeFormatter);
    }

    // TODO: this should be outsourced into a separate class
    protected byte[] derivePsk(PskSet pskSet) {
        try {
            LOGGER.debug("Deriving PSK from current session");
            HKDFAlgorithm hkdfAlgorithm =
                AlgorithmResolver.getHKDFAlgorithm(context.getChooser().getSelectedCipherSuite());
            DigestAlgorithm digestAlgo = AlgorithmResolver.getDigestAlgorithm(
                context.getChooser().getSelectedProtocolVersion(), context.getChooser().getSelectedCipherSuite());
            int macLength = Mac.getInstance(hkdfAlgorithm.getMacAlgorithm().getJavaName()).getMacLength();
            byte[] resumptionMasterSecret = HKDFunction.deriveSecret(hkdfAlgorithm, digestAlgo.getJavaName(),
                context.getChooser().getMasterSecret(), HKDFunction.RESUMPTION_MASTER_SECRET,
                context.getDigest().getRawBytes());
            context.setResumptionMasterSecret(resumptionMasterSecret);
            LOGGER.debug("Derived ResumptionMasterSecret: " + ArrayConverter.bytesToHexString(resumptionMasterSecret));
            LOGGER.debug("Handshake Transcript Raw Bytes: "
                + ArrayConverter.bytesToHexString(context.getDigest().getRawBytes()));
            byte[] psk = HKDFunction.expandLabel(hkdfAlgorithm, resumptionMasterSecret, HKDFunction.RESUMPTION,
                pskSet.getTicketNonce(), macLength);
            LOGGER.debug("New derived pre-shared-key: " + ArrayConverter.bytesToHexString(psk));
            return psk;

        } catch (NoSuchAlgorithmException | CryptoException ex) {
            LOGGER.error("DigestAlgorithm for psk derivation unknown");
            throw new WorkflowExecutionException(ex);
        }
    }
}
