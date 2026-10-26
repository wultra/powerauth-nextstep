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
import com.wultra.security.powerauth.app.nextstep.repository.UserIdentityRepository;
import com.wultra.security.powerauth.app.nextstep.repository.catalogue.RepositoryCatalogue;
import com.wultra.security.powerauth.app.nextstep.repository.model.entity.OtpDefinitionEntity;
import com.wultra.security.powerauth.app.nextstep.repository.model.entity.OtpEntity;
import com.wultra.security.powerauth.app.nextstep.repository.model.entity.UserContactEntity;
import com.wultra.security.powerauth.app.nextstep.service.catalogue.ServiceCatalogue;
import com.wultra.security.powerauth.lib.nextstep.model.entity.enumeration.AuthenticationResult;
import com.wultra.security.powerauth.lib.nextstep.model.entity.enumeration.ContactType;
import com.wultra.security.powerauth.lib.nextstep.model.entity.enumeration.ContactVerificationMethod;
import com.wultra.security.powerauth.lib.nextstep.model.entity.enumeration.OtpStatus;
import com.wultra.security.powerauth.lib.nextstep.model.enumeration.OtpGenerationAlgorithm;
import com.wultra.security.powerauth.lib.nextstep.model.exception.*;
import com.wultra.security.powerauth.lib.nextstep.model.request.ConfirmContactVerificationRequest;
import com.wultra.security.powerauth.lib.nextstep.model.request.CreateOtpRequest;
import com.wultra.security.powerauth.lib.nextstep.model.request.DeleteOtpRequest;
import com.wultra.security.powerauth.lib.nextstep.model.request.OtpAuthenticationRequest;
import com.wultra.security.powerauth.lib.nextstep.model.request.StartContactVerificationRequest;
import com.wultra.security.powerauth.lib.nextstep.model.response.ConfirmContactVerificationResponse;
import com.wultra.security.powerauth.lib.nextstep.model.response.CreateOtpResponse;
import com.wultra.security.powerauth.lib.nextstep.model.response.OtpAuthenticationResponse;
import com.wultra.security.powerauth.lib.nextstep.model.response.StartContactVerificationResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.List;
import java.util.stream.Stream;

/**
 * This service handles verification of user contacts using an OTP or a deeplink. The OTP value or deeplink URL is returned
 * to the caller, who is responsible for delivering it to the contact.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Service
@Slf4j
public class ContactVerificationService {

    private static final String AUDIT_TYPE_USER_IDENTITY = "USER_IDENTITY";

    private final ServiceCatalogue serviceCatalogue;
    private final OtpRepository otpRepository;
    private final UserIdentityRepository userIdentityRepository;
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
        this.userIdentityRepository = repositoryCatalogue.getUserIdentityRepository();
        this.serviceCatalogue = serviceCatalogue;
        this.audit = audit;
    }

    /**
     * Start verification of a user contact by issuing an OTP, optionally wrapped into a deeplink. The OTP value or deeplink
     * URL is returned to the caller for delivery to the contact.
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
        final ContactVerificationMethod method = request.getMethod();
        if (method != ContactVerificationMethod.OTP && method != ContactVerificationMethod.DEEPLINK) {
            throw new InvalidRequestException("Only OTP or DEEPLINK contact verification may be started, method: " + method);
        }
        final boolean deeplink = method == ContactVerificationMethod.DEEPLINK;
        if (deeplink) {
            validateDeeplinkBaseUrl(request.getDeeplinkBaseUrl());
        }

        final UserContactEntity contact = lockAndFindContact(request.getUserId(), request.getContactName(), request.getContactType());

        // A digest-based OTP would be a deterministic, predictable value derived from the binding hash.
        final OtpDefinitionEntity otpDefinition = serviceCatalogue.getOtpDefinitionService().findActiveOtpDefinition(request.getOtpDefinitionName());
        if (otpDefinition.getOtpPolicy().getGenAlgorithm() == OtpGenerationAlgorithm.OTP_DATA_DIGEST) {
            throw new InvalidConfigurationException("Contact verification OTP definition must use a random generation algorithm, definition: " + request.getOtpDefinitionName());
        }
        // Without an attempt limit or expiration the OTP could be guessed or used indefinitely. The proxy branch needs
        // an operation, which this operation-less flow does not have.
        if (otpDefinition.getOtpPolicy().getAttemptLimit() == null || otpDefinition.getOtpPolicy().getExpirationTime() == null
                || otpDefinition.isDataAdapterProxyEnabled()) {
            throw new InvalidConfigurationException("Contact verification OTP definition must define an attempt limit and expiration time and must not be data adapter proxy enabled, definition: " + request.getOtpDefinitionName());
        }

        final String bindingHash = computeBindingHash(contact);
        removeActiveVerifications(request.getUserId(), bindingHash);

        final CreateOtpRequest createOtpRequest = new CreateOtpRequest();
        createOtpRequest.setUserId(request.getUserId());
        createOtpRequest.setOtpName(request.getOtpDefinitionName());
        createOtpRequest.setOtpData(bindingHash);
        final CreateOtpResponse createOtpResponse = serviceCatalogue.getOtpService().createOtp(createOtpRequest);
        final OtpEntity otp = serviceCatalogue.getOtpService().findOtp(createOtpResponse.getOtpId(), null);
        // Marks the OTP as issued by this flow so that confirmation, cleanup and the generic OTP endpoint can tell it apart.
        otp.setVerificationMethod(method);
        otpRepository.save(otp);

        final StartContactVerificationResponse response = new StartContactVerificationResponse();
        response.setVerificationId(createOtpResponse.getOtpId());
        response.setContactName(contact.getName());
        response.setContactValue(contact.getValue());
        response.setContactType(contact.getType());
        response.setMethod(method);
        response.setExpiresAt(otp.getTimestampExpires());
        if (deeplink) {
            response.setDeeplinkUrl(buildDeeplink(request.getDeeplinkBaseUrl(), createOtpResponse.getOtpValue()));
        } else {
            response.setOtpValue(createOtpResponse.getOtpValue());
        }

        logger.debug("Contact verification started, user ID: {}, contact name: {}, method: {}", request.getUserId(), contact.getName(), method);
        return response;
    }

    /**
     * Confirm verification of a user contact using the OTP value or deeplink token supplied by the caller.
     * @param request Confirm contact verification request.
     * @return Confirm contact verification response.
     * @throws UserNotFoundException Thrown when user identity is not found.
     * @throws UserContactNotFoundException Thrown when user contact is not found.
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
    public ConfirmContactVerificationResponse confirmContactVerification(ConfirmContactVerificationRequest request) throws UserNotFoundException, UserContactNotFoundException,
            InvalidRequestException, InvalidConfigurationException, OperationNotFoundException, CredentialNotFoundException, OperationAlreadyCanceledException,
            OperationAlreadyFinishedException, AuthMethodNotFoundException, OperationAlreadyFailedException, OperationNotValidException, EncryptionException {
        final UserContactEntity contact = lockAndFindContact(request.getUserId(), request.getContactName(), request.getContactType());

        // The OTP must be bound to the current user and contact value, otherwise it was issued for a different contact or value.
        final OtpEntity otp;
        try {
            otp = serviceCatalogue.getOtpService().findOtp(request.getVerificationId(), null);
        } catch (OtpNotFoundException ex) {
            return failed();
        }
        if (!request.getUserId().equals(otp.getUserId()) || !computeBindingHash(contact).equals(otp.getOtpData())) {
            return failed();
        }

        // The persisted method decides which credential is accepted; a null method means the OTP was not issued by this flow.
        final ContactVerificationMethod method = otp.getVerificationMethod();
        final String credential = method == ContactVerificationMethod.OTP ? request.getOtpValue()
                : method == ContactVerificationMethod.DEEPLINK ? request.getToken() : null;
        if (credential == null) {
            return failed();
        }

        // The OTP definition is mutable: a removed attempt limit, a lowered limit below the recorded failures, or proxy mode
        // enabled after the start must not allow further guesses or authentication without an operation.
        final Integer attemptLimit = otp.getOtpDefinition().getOtpPolicy().getAttemptLimit();
        if (otp.getOtpDefinition().isDataAdapterProxyEnabled() || attemptLimit == null || otp.getFailedAttemptCounter() >= attemptLimit) {
            try {
                invalidateOtp(otp.getOtpId());
            } catch (OtpNotFoundException ex) {
                // Already removed, nothing to invalidate.
            }
            return failed();
        }

        final OtpAuthenticationRequest authRequest = new OtpAuthenticationRequest();
        authRequest.setOtpId(request.getVerificationId());
        authRequest.setOtpValue(credential);
        authRequest.setCheckOnly(false);
        authRequest.setUpdateOperation(false);
        final OtpAuthenticationResponse authResponse;
        try {
            authResponse = serviceCatalogue.getAuthenticationService().authenticateWithOtpInternal(authRequest);
        } catch (OtpNotFoundException ex) {
            return failed();
        }

        final ConfirmContactVerificationResponse response = new ConfirmContactVerificationResponse();
        response.setRemainingAttempts(authResponse.getRemainingAttempts());
        if (authResponse.getAuthenticationResult() == AuthenticationResult.SUCCEEDED) {
            serviceCatalogue.getUserContactService().markContactVerified(request.getUserId(), contact.getName(), contact.getType(), method);
            audit.info("Contact verification confirmed", AuditDetail.builder()
                    .type(AUDIT_TYPE_USER_IDENTITY)
                    .param("userId", request.getUserId())
                    .param("contactName", contact.getName())
                    .param("method", method)
                    .build());
            response.setVerified(true);
            response.setVerificationMethod(method);
            response.setTimestampVerified(contact.getTimestampVerified());
        }
        return response;
    }

    private ConfirmContactVerificationResponse failed() {
        final ConfirmContactVerificationResponse response = new ConfirmContactVerificationResponse();
        response.setVerified(false);
        return response;
    }

    private UserContactEntity lockAndFindContact(String userId, String contactName, ContactType contactType) throws UserNotFoundException, UserContactNotFoundException {
        // Serialize with other verification and contact changes of the same user; findUser also rejects removed users.
        userIdentityRepository.findAndLockByUserId(userId);
        return serviceCatalogue.getUserIdentityLookupService().findUser(userId).getContacts().stream()
                .filter(c -> c.getName().equals(contactName) && c.getType() == contactType)
                .findFirst()
                .orElseThrow(() -> new UserContactNotFoundException("User contact not found: " + contactName + ", user ID: " + userId + ", type: " + contactType));
    }

    /**
     * Invalidate pending (ACTIVE) verification OTPs bound to the given contact state, so that they cannot be revived
     * when the contact value is later changed back or the contact is re-created. Call under the per-user lock.
     * @param contact Contact entity with the state to invalidate.
     */
    public void invalidatePendingVerifications(UserContactEntity contact) {
        try {
            removeActiveVerifications(contact.getUser().getUserId(), computeBindingHash(contact));
        } catch (OtpNotFoundException | OperationNotFoundException | InvalidRequestException ex) {
            // Roll back instead of leaving a stale pending verification in place.
            throw new IllegalStateException("Failed to invalidate pending contact verifications", ex);
        }
    }

    private void removeActiveVerifications(String userId, String bindingHash) throws OtpNotFoundException, OperationNotFoundException, InvalidRequestException {
        final List<String> otpIds;
        // Filtered in memory: otp_data is a CLOB on Oracle and cannot be compared in SQL.
        try (final Stream<OtpEntity> activeOtps = otpRepository.findAllByUserIdAndStatus(userId, OtpStatus.ACTIVE)) {
            otpIds = activeOtps.filter(otp -> otp.getVerificationMethod() != null && bindingHash.equals(otp.getOtpData())).map(OtpEntity::getOtpId).toList();
        }
        for (String otpId : otpIds) {
            invalidateOtp(otpId);
        }
    }

    private void invalidateOtp(String otpId) throws OtpNotFoundException, OperationNotFoundException, InvalidRequestException {
        final DeleteOtpRequest request = new DeleteOtpRequest();
        request.setOtpId(otpId);
        serviceCatalogue.getOtpService().deleteOtp(request);
    }

    /**
     * Compute a SHA-256 hex hash binding the OTP to the contact name, type and value. Each field is prefixed with its
     * length so that distinct contacts can never serialize identically.
     */
    private String computeBindingHash(UserContactEntity contact) {
        final String type = contact.getType().name();
        final String input = contact.getName().length() + ":" + contact.getName() + type.length() + ":" + type + contact.getValue().length() + ":" + contact.getValue();
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(input.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-256 algorithm is not available", ex);
        }
    }

    private void validateDeeplinkBaseUrl(String baseUrl) throws InvalidRequestException {
        if (baseUrl == null) {
            throw new InvalidRequestException("Deeplink base URL is required for the DEEPLINK method");
        }
        try {
            final URI uri = new URI(baseUrl);
            if (uri.getScheme() == null || uri.getFragment() != null) {
                // A fragment would swallow the appended token query parameter
                throw new InvalidRequestException("Deeplink base URL must be an absolute URI without a fragment");
            }
        } catch (URISyntaxException ex) {
            throw new InvalidRequestException("Deeplink base URL is not a valid URI");
        }
    }

    private String buildDeeplink(String baseUrl, String otpValue) {
        final String encodedToken = URLEncoder.encode(otpValue, StandardCharsets.UTF_8);
        return baseUrl + (baseUrl.contains("?") ? "&" : "?") + "token=" + encodedToken;
    }

}
