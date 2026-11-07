/*
 * PowerAuth Web Flow and related software components
 * Copyright (C) 2026 Wultra s.r.o.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package com.wultra.security.powerauth.app.nextstep.service;

import com.wultra.core.audit.base.Audit;
import com.wultra.core.audit.base.model.AuditDetail;
import com.wultra.security.powerauth.app.nextstep.repository.OtpRepository;
import com.wultra.security.powerauth.app.nextstep.repository.catalogue.RepositoryCatalogue;
import com.wultra.security.powerauth.app.nextstep.repository.model.entity.OtpDefinitionEntity;
import com.wultra.security.powerauth.app.nextstep.repository.model.entity.OtpEntity;
import com.wultra.security.powerauth.app.nextstep.repository.model.entity.UserContactEntity;
import com.wultra.security.powerauth.app.nextstep.service.catalogue.ServiceCatalogue;
import com.wultra.security.powerauth.lib.nextstep.model.entity.enumeration.AuthenticationResult;
import com.wultra.security.powerauth.lib.nextstep.model.entity.enumeration.ContactType;
import com.wultra.security.powerauth.lib.nextstep.model.entity.enumeration.ContactVerificationMethod;
import com.wultra.security.powerauth.lib.nextstep.model.entity.enumeration.OtpPurpose;
import com.wultra.security.powerauth.lib.nextstep.model.entity.enumeration.OtpStatus;
import com.wultra.security.powerauth.lib.nextstep.model.exception.*;
import com.wultra.security.powerauth.lib.nextstep.model.request.ConfirmContactVerificationRequest;
import com.wultra.security.powerauth.lib.nextstep.model.request.DeleteOtpRequest;
import com.wultra.security.powerauth.lib.nextstep.model.request.OtpAuthenticationRequest;
import com.wultra.security.powerauth.lib.nextstep.model.request.StartContactVerificationRequest;
import com.wultra.security.powerauth.lib.nextstep.model.response.ConfirmContactVerificationResponse;
import com.wultra.security.powerauth.lib.nextstep.model.response.CreateOtpResponse;
import com.wultra.security.powerauth.lib.nextstep.model.response.OtpAuthenticationResponse;
import com.wultra.security.powerauth.lib.nextstep.model.response.StartContactVerificationResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.List;
import java.util.stream.Stream;

/**
 * This service handles verification of user contacts using an OTP. The OTP value is returned to the caller, who is
 * responsible for delivering it to the contact.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Service
public class ContactVerificationService {

    private static final Logger logger = LoggerFactory.getLogger(ContactVerificationService.class);

    private static final String AUDIT_TYPE_USER_IDENTITY = "USER_IDENTITY";

    private final ServiceCatalogue serviceCatalogue;
    private final OtpRepository otpRepository;
    private final Audit audit;

    /**
     * Contact verification service constructor.
     * @param repositoryCatalogue Repository catalogue.
     * @param serviceCatalogue Service catalogue.
     * @param audit Audit interface.
     */
    @Autowired
    public ContactVerificationService(RepositoryCatalogue repositoryCatalogue, @Lazy ServiceCatalogue serviceCatalogue, Audit audit) {
        this.otpRepository = repositoryCatalogue.getOtpRepository();
        this.serviceCatalogue = serviceCatalogue;
        this.audit = audit;
    }

    /**
     * Start verification of a user contact by issuing an OTP. The OTP value is returned to the caller for delivery to the contact.
     * @param request Start contact verification request.
     * @return Start contact verification response.
     * @throws UserNotFoundException Thrown when user identity is not found.
     * @throws UserContactNotFoundException Thrown when user contact is not found.
     * @throws InvalidRequestException Thrown when the request is invalid.
     * @throws InvalidConfigurationException Thrown when the OTP definition configuration is invalid.
     * @throws OtpDefinitionNotFoundException Thrown when the OTP definition is not found.
     * @throws UserNotActiveException Thrown when the user identity is not active.
     * @throws CredentialDefinitionNotFoundException Thrown when a credential definition is not found.
     * @throws OperationNotFoundException Thrown when an operation is not found.
     * @throws OtpGenAlgorithmNotSupportedException Thrown when the OTP generation algorithm is not supported.
     * @throws OperationAlreadyFinishedException Thrown when an operation is already finished.
     * @throws OperationAlreadyFailedException Thrown when an operation is already failed.
     * @throws CredentialNotActiveException Thrown when a credential is not active.
     * @throws CredentialNotFoundException Thrown when a credential is not found.
     * @throws OtpNotFoundException Thrown when the created OTP cannot be read back.
     * @throws EncryptionException Thrown when encryption or decryption fails.
     */
    @Transactional(rollbackFor = Exception.class)
    public StartContactVerificationResponse startContactVerification(StartContactVerificationRequest request) throws UserNotFoundException, UserContactNotFoundException,
            InvalidRequestException, InvalidConfigurationException, OtpDefinitionNotFoundException, UserNotActiveException, CredentialDefinitionNotFoundException,
            OperationNotFoundException, OtpGenAlgorithmNotSupportedException, OperationAlreadyFinishedException, OperationAlreadyFailedException,
            CredentialNotActiveException, CredentialNotFoundException, OtpNotFoundException, EncryptionException {
        final UserContactEntity contact = findContact(request.getUserId(), request.getContactName(), request.getContactType());

        final OtpDefinitionEntity otpDefinition = serviceCatalogue.getOtpDefinitionService().findActiveOtpDefinition(request.getOtpDefinitionName());
        // Without an attempt limit or expiration the OTP could be guessed or used indefinitely. The proxy branch needs
        // an operation, which this operation-less flow does not have.
        if (otpDefinition.getOtpPolicy().getAttemptLimit() == null || otpDefinition.getOtpPolicy().getExpirationTime() == null
                || otpDefinition.isDataAdapterProxyEnabled()) {
            throw new InvalidConfigurationException("Contact verification OTP definition must define an attempt limit and expiration time and must not be data adapter proxy enabled, definition: " + request.getOtpDefinitionName());
        }

        final String bindingHash = computeBindingHash(contact);
        removeActiveVerifications(request.getUserId());

        final CreateOtpResponse createOtpResponse = serviceCatalogue.getOtpService().createContactVerificationOtp(otpDefinition, request.getUserId(), bindingHash);
        final OtpEntity otp = serviceCatalogue.getOtpService().findOtp(createOtpResponse.getOtpId(), null);
        logger.info("Contact verification started, verification ID: {}", otp.getOtpId());

        final StartContactVerificationResponse response = new StartContactVerificationResponse();
        response.setVerificationId(createOtpResponse.getOtpId());
        response.setExpiresAt(otp.getTimestampExpires());
        response.setOtpValue(createOtpResponse.getOtpValue());
        return response;
    }

    /**
     * Confirm verification of a user contact using the OTP value supplied by the caller.
     * @param request Confirm contact verification request.
     * @return Confirm contact verification response.
     * @throws InvalidRequestException Thrown when the request is invalid.
     * @throws InvalidConfigurationException Thrown when the configuration is invalid.
     * @throws OperationNotFoundException Thrown when an operation is not found.
     * @throws CredentialNotFoundException Thrown when a credential is not found.
     * @throws OperationAlreadyCanceledException Thrown when an operation is already canceled.
     * @throws OperationAlreadyFinishedException Thrown when an operation is already finished.
     * @throws AuthMethodNotFoundException Thrown when an authentication method is not found.
     * @throws OperationAlreadyFailedException Thrown when an operation is already failed.
     * @throws OperationNotValidException Thrown when an operation is not valid.
     * @throws EncryptionException Thrown when encryption or decryption fails.
     */
    @Transactional
    public ConfirmContactVerificationResponse confirmContactVerification(ConfirmContactVerificationRequest request) throws InvalidRequestException, InvalidConfigurationException, OperationNotFoundException, CredentialNotFoundException, OperationAlreadyCanceledException,
            OperationAlreadyFinishedException, AuthMethodNotFoundException, OperationAlreadyFailedException, OperationNotValidException, EncryptionException {
        final UserContactEntity contact;
        try {
            contact = findContact(request.getUserId(), request.getContactName(), request.getContactType());
        } catch (UserNotFoundException | UserContactNotFoundException ex) {
            logger.debug("Contact verification failed, user or contact not found", ex);
            return failed(request.getVerificationId(), "user or contact not found");
        }

        // The OTP must be bound to the current user and contact value, otherwise it was issued for a different contact or value.
        final OtpEntity otp;
        try {
            otp = serviceCatalogue.getOtpService().findOtp(request.getVerificationId(), null);
        } catch (OtpNotFoundException ex) {
            logger.debug("Contact verification OTP not found", ex);
            return failed(request.getVerificationId(), "verification not found");
        }
        if (!request.getUserId().equals(otp.getUserId()) || !computeBindingHash(contact).equals(otp.getOtpData())) {
            return failed(request.getVerificationId(), "verification does not match the user or contact");
        }

        if (otp.getOtpPurpose() != OtpPurpose.CONTACT_VERIFICATION) {
            return failed(request.getVerificationId(), "OTP was not issued for contact verification");
        }

        // The OTP definition is mutable: a removed attempt limit, a lowered limit below the recorded failures, or proxy mode
        // enabled after the start must not allow further guesses or authentication without an operation.
        final Integer attemptLimit = otp.getOtpDefinition().getOtpPolicy().getAttemptLimit();
        if (otp.getOtpDefinition().isDataAdapterProxyEnabled() || attemptLimit == null || otp.getFailedAttemptCounter() >= attemptLimit) {
            invalidateOtp(otp.getOtpId());
            return failed(request.getVerificationId(), "attempt limit reached or OTP definition no longer valid");
        }

        final OtpAuthenticationRequest authRequest = new OtpAuthenticationRequest();
        authRequest.setOtpId(request.getVerificationId());
        authRequest.setOtpValue(request.getOtpValue());
        authRequest.setCheckOnly(false);
        authRequest.setUpdateOperation(false);
        final OtpAuthenticationResponse authResponse;
        try {
            authResponse = serviceCatalogue.getAuthenticationService().authenticateWithOtpInternal(authRequest, otp);
        } catch (OtpNotFoundException ex) {
            logger.debug("Contact verification OTP disappeared during confirmation", ex);
            return failed(request.getVerificationId(), "verification no longer exists");
        }

        final ConfirmContactVerificationResponse response = new ConfirmContactVerificationResponse();
        response.setRemainingAttempts(authResponse.getRemainingAttempts());
        if (authResponse.getAuthenticationResult() == AuthenticationResult.SUCCEEDED) {
            logger.info("Contact verification OTP was accepted, verification ID: {}", request.getVerificationId());
            serviceCatalogue.getUserContactService().markContactVerified(contact, ContactVerificationMethod.OTP);
            audit.info("Contact verification confirmed", AuditDetail.builder()
                    .type(AUDIT_TYPE_USER_IDENTITY)
                    .param("userId", request.getUserId())
                    .param("contactName", contact.getName())
                    .param("method", ContactVerificationMethod.OTP)
                    .build());
            response.setVerified(true);
            response.setVerificationMethod(ContactVerificationMethod.OTP);
            response.setTimestampVerified(contact.getTimestampVerified());
        } else {
            logger.info("Contact verification OTP was not accepted, verification ID: {}, remaining attempts: {}", request.getVerificationId(), authResponse.getRemainingAttempts());
        }
        return response;
    }

    private ConfirmContactVerificationResponse failed(String verificationId, String reason) {
        logger.info("Contact verification rejected, verification ID: {}, reason: {}", verificationId, reason);
        final ConfirmContactVerificationResponse response = new ConfirmContactVerificationResponse();
        response.setVerified(false);
        return response;
    }

    private UserContactEntity findContact(String userId, String contactName, ContactType contactType) throws UserNotFoundException, UserContactNotFoundException {
        return serviceCatalogue.getUserIdentityLookupService().findUser(userId).getContacts().stream()
                .filter(c -> c.getName().equals(contactName) && c.getType() == contactType)
                .findFirst()
                .orElseThrow(() -> new UserContactNotFoundException("User contact not found: " + contactName + ", user ID: " + userId + ", type: " + contactType));
    }

    /**
     * Invalidate pending contact verification OTPs of the contact's user, so that they cannot be revived
     * when the contact value is later changed back or the contact is re-created. Pending verifications of the user's
     * other contacts are invalidated as well.
     * @param contact Contact entity whose user's pending verifications are invalidated.
     */
    public void invalidatePendingVerifications(UserContactEntity contact) {
        try {
            removeActiveVerifications(contact.getUser().getUserId());
        } catch (OperationNotFoundException | InvalidRequestException ex) {
            // Roll back instead of leaving a stale pending verification in place.
            throw new IllegalStateException("Failed to invalidate pending contact verifications", ex);
        }
    }

    private void removeActiveVerifications(String userId) throws OperationNotFoundException, InvalidRequestException {
        final List<String> otpIds;
        try (final Stream<OtpEntity> activeOtps = otpRepository.findAllByUserIdAndStatusAndOtpPurpose(userId, OtpStatus.ACTIVE, OtpPurpose.CONTACT_VERIFICATION)) {
            otpIds = activeOtps.map(OtpEntity::getOtpId).toList();
        }
        for (String otpId : otpIds) {
            invalidateOtp(otpId);
        }
    }

    /**
     * Invalidate an OTP. The operation is idempotent: an OTP that is already removed or missing is left as is.
     */
    private void invalidateOtp(String otpId) throws OperationNotFoundException, InvalidRequestException {
        final DeleteOtpRequest request = new DeleteOtpRequest();
        request.setOtpId(otpId);
        try {
            serviceCatalogue.getOtpService().deleteOtp(request);
        } catch (OtpNotFoundException ex) {
            logger.debug("OTP is already removed, nothing to invalidate, OTP ID: {}", otpId, ex);
        }
    }

    /**
     * Compute a SHA-256 Base64 hash binding the OTP to the contact name, type and value. Each field is prefixed
     * with its length in bytes, so the encoding is unambiguous for any field content.
     */
    private String computeBindingHash(UserContactEntity contact) {
        try {
            final MessageDigest md = MessageDigest.getInstance("SHA-256");
            for (final String field : List.of(contact.getName(), contact.getType().name(), contact.getValue())) {
                final byte[] bytes = field.getBytes(StandardCharsets.UTF_8);
                md.update(ByteBuffer.allocate(Integer.BYTES).putInt(bytes.length).array());
                md.update(bytes);
            }
            return Base64.getEncoder().encodeToString(md.digest());
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-256 algorithm is not available", ex);
        }
    }

}
