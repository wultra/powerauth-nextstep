/*
 * PowerAuth Web Flow and related software components
 * Copyright (C) 2025 Wultra s.r.o.
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
import com.wultra.security.powerauth.app.nextstep.configuration.ContactVerificationConfiguration;
import com.wultra.security.powerauth.app.nextstep.repository.OtpRepository;
import com.wultra.security.powerauth.app.nextstep.repository.UserIdentityRepository;
import com.wultra.security.powerauth.app.nextstep.repository.catalogue.RepositoryCatalogue;
import com.wultra.security.powerauth.app.nextstep.repository.model.entity.OtpDefinitionEntity;
import com.wultra.security.powerauth.app.nextstep.repository.model.entity.OtpEntity;
import com.wultra.security.powerauth.app.nextstep.repository.model.entity.UserContactEntity;
import com.wultra.security.powerauth.app.nextstep.repository.model.entity.UserIdentityEntity;
import com.wultra.security.powerauth.app.nextstep.service.catalogue.ServiceCatalogue;
import com.wultra.security.powerauth.lib.nextstep.model.entity.enumeration.AuthenticationResult;
import com.wultra.security.powerauth.lib.nextstep.model.entity.enumeration.ContactType;
import com.wultra.security.powerauth.lib.nextstep.model.entity.enumeration.ContactVerificationMethod;
import com.wultra.security.powerauth.lib.nextstep.model.entity.enumeration.OtpStatus;
import com.wultra.security.powerauth.lib.nextstep.model.enumeration.OtpGenerationAlgorithm;
import com.wultra.security.powerauth.lib.nextstep.model.exception.*;
import com.wultra.security.powerauth.lib.nextstep.model.request.CreateOtpRequest;
import com.wultra.security.powerauth.lib.nextstep.model.request.DeleteOtpRequest;
import com.wultra.security.powerauth.lib.nextstep.model.request.OtpAuthenticationRequest;
import com.wultra.security.powerauth.lib.nextstep.model.request.ConfirmContactVerificationRequest;
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
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;

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
    private static final Set<String> DANGEROUS_SCHEMES = Set.of("javascript", "data", "file", "vbscript");

    private final ServiceCatalogue serviceCatalogue;
    private final OtpRepository otpRepository;
    private final UserIdentityRepository userIdentityRepository;
    private final Audit audit;
    private final ContactVerificationConfiguration configuration;

    /**
     * Contact verification service constructor.
     * @param repositoryCatalogue Repository catalogue.
     * @param serviceCatalogue Service catalogue.
     * @param audit Audit interface.
     * @param configuration Contact verification configuration.
     */
    @Autowired
    public ContactVerificationService(RepositoryCatalogue repositoryCatalogue, @Lazy ServiceCatalogue serviceCatalogue, Audit audit, ContactVerificationConfiguration configuration) {
        this.serviceCatalogue = serviceCatalogue;
        this.otpRepository = repositoryCatalogue.getOtpRepository();
        this.userIdentityRepository = repositoryCatalogue.getUserIdentityRepository();
        this.audit = audit;
        this.configuration = configuration;
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

        // Acquire a pessimistic write lock on the user identity to serialize concurrent start/confirm and contact-value
        // updates for the same user, so OTP issuance cannot interleave with a confirmation or a contact value change.
        userIdentityRepository.findAndLockByUserId(request.getUserId()).orElseThrow(() ->
                new UserNotFoundException("User identity not found: " + request.getUserId()));

        final UserContactEntity contact = findContact(request.getUserId(), request.getContactName(), request.getContactType());
        final String bindingHash = computeBindingHash(contact.getName(), contact.getType(), contact.getValue());

        // Guard: the referenced OTP definition must use a random generation algorithm, otherwise the value would be a
        // deterministic digest of the binding hash and therefore predictable.
        final OtpDefinitionEntity otpDefinition = serviceCatalogue.getOtpDefinitionService().findActiveOtpDefinition(request.getOtpDefinitionName());
        if (otpDefinition.getOtpPolicy().getGenAlgorithm() == OtpGenerationAlgorithm.OTP_DATA_DIGEST) {
            throw new InvalidConfigurationException("Contact verification OTP definition must use a random generation algorithm, definition: " + request.getOtpDefinitionName());
        }
        // Guard: a finite attempt limit is required, otherwise the OTP value could be guessed without bound within the
        // expiry window (this service enforces the attempt limit itself; OtpService does not for operation-less OTPs).
        if (otpDefinition.getOtpPolicy().getAttemptLimit() == null) {
            throw new InvalidConfigurationException("Contact verification OTP definition must define an attempt limit, definition: " + request.getOtpDefinitionName());
        }
        // Guard: a finite expiration is required, otherwise an unexpiring verification OTP would remain valid indefinitely.
        if (otpDefinition.getOtpPolicy().getExpirationTime() == null) {
            throw new InvalidConfigurationException("Contact verification OTP definition must define an expiration time, definition: " + request.getOtpDefinitionName());
        }
        // Reject proxy-enabled definitions: the proxy branch has no operation in this operation-less flow and would NPE at confirmation.
        if (otpDefinition.isDataAdapterProxyEnabled()) {
            throw new InvalidConfigurationException("Contact verification OTP definition must not be data adapter proxy enabled, definition: " + request.getOtpDefinitionName());
        }

        // Build the deeplink URL eagerly for the DEEPLINK method so that an invalid base URL fails before any OTP is issued.
        final boolean deeplink = method == ContactVerificationMethod.DEEPLINK;
        if (deeplink) {
            validateDeeplinkConfiguration(request.getDeeplinkBaseUrl());
            validateMessageTemplate(request.getMessageTemplate());
        }

        // Ensure a single active verification per (user, contact) by removing earlier active OTPs for the same binding.
        removeActiveVerifications(request.getUserId(), bindingHash);

        final CreateOtpRequest createOtpRequest = new CreateOtpRequest();
        createOtpRequest.setUserId(request.getUserId());
        createOtpRequest.setOtpName(request.getOtpDefinitionName());
        createOtpRequest.setOtpData(bindingHash);
        final CreateOtpResponse createOtpResponse = serviceCatalogue.getOtpService().createOtp(createOtpRequest);
        final String otpId = createOtpResponse.getOtpId();
        final String otpValue = createOtpResponse.getOtpValue();
        final OtpEntity otp = serviceCatalogue.getOtpService().findOtp(otpId, null);
        // Persist the started verification method on the OTP so that confirmation can authoritatively check it
        // instead of inferring it from the supplied credential.
        otp.setVerificationMethod(method);
        otpRepository.save(otp);

        final StartContactVerificationResponse response = new StartContactVerificationResponse();
        response.setVerificationId(otpId);
        response.setContactName(contact.getName());
        response.setContactValue(contact.getValue());
        response.setContactType(contact.getType());
        response.setMethod(method);
        response.setExpiresAt(otp.getTimestampExpires());
        if (deeplink) {
            response.setDeeplinkUrl(buildDeeplink(request.getDeeplinkBaseUrl(), request.getMessageTemplate(), otpValue));
        } else {
            response.setOtpValue(otpValue);
        }

        logger.debug("Contact verification started, user ID: {}, contact name: {}, method: {}", request.getUserId(), contact.getName(), method);
        audit.info("Contact verification started", AuditDetail.builder()
                .type(AUDIT_TYPE_USER_IDENTITY)
                .param("userId", request.getUserId())
                .param("contactName", contact.getName())
                .param("contactType", contact.getType())
                .param("method", method)
                .build());
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
        final UserContactEntity contact;
        try {
            // Acquire a pessimistic write lock on the user identity first, serializing concurrent confirmations and
            // contact-value updates for the same user so attempt counters cannot be lost and two confirms cannot both succeed.
            userIdentityRepository.findAndLockByUserId(request.getUserId()).orElseThrow(() ->
                    new UserNotFoundException("User identity not found: " + request.getUserId()));
            contact = findContact(request.getUserId(), request.getContactName(), request.getContactType());
        } catch (UserNotFoundException | UserContactNotFoundException ex) {
            // Do not reveal whether the user or contact exists; an unknown user/contact fails generically, exactly like a wrong OTP.
            return failed(null);
        }
        final String otpId = request.getVerificationId();

        final OtpEntity otp;
        try {
            otp = serviceCatalogue.getOtpService().findOtp(otpId, null);
        } catch (OtpNotFoundException ex) {
            return failed(null);
        }

        // Bind the OTP to the current user and contact value; any mismatch results in a generic failure without revealing the cause.
        // This re-check runs under the pessimistic user lock, so a stale contact value cannot overwrite a newer one.
        final String bindingHash = computeBindingHash(contact.getName(), contact.getType(), contact.getValue());
        if (!request.getUserId().equals(otp.getUserId()) || !bindingHash.equals(otp.getOtpData())) {
            return failed(null);
        }

        // Read the authoritatively persisted verification method. A null method means this OTP was not issued by the
        // contact verification flow and must not be confirmed here.
        final ContactVerificationMethod method = otp.getVerificationMethod();
        if (method == null) {
            return failed(null);
        }
        // The supplied credential channel must match the started method: OTP method is confirmed with otpValue,
        // DEEPLINK method with token. A mismatched or missing credential fails generically.
        final String otpValueToVerify;
        switch (method) {
            case OTP -> otpValueToVerify = request.getOtpValue();
            case DEEPLINK -> otpValueToVerify = request.getToken();
            default -> otpValueToVerify = null;
        }
        if (otpValueToVerify == null) {
            return failed(null);
        }

        final Integer attemptLimit = otp.getOtpDefinition().getOtpPolicy().getAttemptLimit();
        if (attemptLimit != null && otp.getFailedAttemptCounter() >= attemptLimit) {
            try {
                blockOtp(otpId);
            } catch (OtpNotFoundException ex) {
                // OTP is already gone, nothing to block.
            }
            return failed(0);
        }

        final OtpAuthenticationRequest authRequest = new OtpAuthenticationRequest();
        authRequest.setOtpId(otpId);
        authRequest.setOtpValue(otpValueToVerify);
        authRequest.setCheckOnly(false);
        authRequest.setUpdateOperation(false);
        final OtpAuthenticationResponse authResponse;
        try {
            authResponse = serviceCatalogue.getAuthenticationService().authenticateWithOtpInternal(authRequest);
        } catch (OtpNotFoundException ex) {
            return failed(null);
        }

        if (authResponse.getAuthenticationResult() == AuthenticationResult.SUCCEEDED) {
            serviceCatalogue.getUserContactService().markContactVerified(request.getUserId(), contact.getName(), contact.getType(), method);
            audit.info("Contact verification confirmed", AuditDetail.builder()
                    .type(AUDIT_TYPE_USER_IDENTITY)
                    .param("userId", request.getUserId())
                    .param("contactName", contact.getName())
                    .param("contactType", contact.getType())
                    .param("method", method)
                    .param("outcome", "SUCCEEDED")
                    .build());
            final ConfirmContactVerificationResponse response = new ConfirmContactVerificationResponse();
            response.setVerified(true);
            response.setRemainingAttempts(authResponse.getRemainingAttempts());
            response.setVerificationMethod(method);
            response.setTimestampVerified(contact.getTimestampVerified());
            return response;
        }

        // Verification failed, enforce the attempt limit by blocking the OTP once the limit is reached.
        final OtpEntity otpAfter;
        try {
            otpAfter = serviceCatalogue.getOtpService().findOtp(otpId, null);
            if (attemptLimit != null && otpAfter.getFailedAttemptCounter() >= attemptLimit) {
                blockOtp(otpId);
            }
        } catch (OtpNotFoundException ex) {
            // OTP is already gone, nothing to block.
        }
        audit.info("Contact verification failed", AuditDetail.builder()
                .type(AUDIT_TYPE_USER_IDENTITY)
                .param("userId", request.getUserId())
                .param("contactName", contact.getName())
                .param("contactType", contact.getType())
                .param("outcome", "FAILED")
                .param("remainingAttempts", authResponse.getRemainingAttempts())
                .build());
        return failed(authResponse.getRemainingAttempts());
    }

    /**
     * Find a user contact by name and type.
     */
    private UserContactEntity findContact(String userId, String contactName, ContactType contactType) throws UserNotFoundException, UserContactNotFoundException {
        final UserIdentityEntity user = serviceCatalogue.getUserIdentityLookupService().findUser(userId);
        final Optional<UserContactEntity> contactOptional = user.getContacts().stream()
                .filter(c -> c.getName().equals(contactName) && c.getType().equals(contactType))
                .findFirst();
        return contactOptional.orElseThrow(() ->
                new UserContactNotFoundException("User contact not found: " + contactName + ", user ID: " + userId + ", type: " + contactType));
    }

    /**
     * Invalidate any pending (ACTIVE) contact-verification OTPs bound to a previous contact value. Because the OTP
     * binding hash is value-specific, removing OTPs bound to the old value on every change prevents a later change back
     * to the old value from reviving a stale verification. Intended to be called under the per-user pessimistic lock.
     * @param userId User identity identifier.
     * @param contactName Contact name.
     * @param contactType Contact type.
     * @param oldValue Previous contact value whose pending verifications should be invalidated.
     * @throws OtpNotFoundException Thrown when an OTP cannot be read back.
     * @throws OperationNotFoundException Thrown when an operation is not found.
     * @throws InvalidRequestException Thrown when the request is invalid.
     */
    public void invalidatePendingContactVerifications(String userId, String contactName, ContactType contactType, String oldValue)
            throws OtpNotFoundException, OperationNotFoundException, InvalidRequestException {
        final String bindingHash = computeBindingHash(contactName, contactType, oldValue);
        removeActiveVerifications(userId, bindingHash);
    }

    /**
     * Remove earlier active verification OTPs for the same user and binding.
     */
    private void removeActiveVerifications(String userId, String bindingHash) throws OtpNotFoundException, OperationNotFoundException, InvalidRequestException {
        final List<OtpEntity> activeOtps = otpRepository.findAllByUserIdAndOtpDataAndStatus(userId, bindingHash, OtpStatus.ACTIVE).toList();
        for (OtpEntity activeOtp : activeOtps) {
            blockOtp(activeOtp.getOtpId());
        }
    }

    /**
     * Invalidate an OTP so that it cannot be retried.
     */
    private void blockOtp(String otpId) throws OtpNotFoundException, OperationNotFoundException, InvalidRequestException {
        final DeleteOtpRequest deleteOtpRequest = new DeleteOtpRequest();
        deleteOtpRequest.setOtpId(otpId);
        serviceCatalogue.getOtpService().deleteOtp(deleteOtpRequest);
    }

    /**
     * Build a generic failed confirmation response, optionally with the number of remaining attempts.
     */
    private ConfirmContactVerificationResponse failed(Integer remainingAttempts) {
        final ConfirmContactVerificationResponse response = new ConfirmContactVerificationResponse();
        response.setVerified(false);
        response.setRemainingAttempts(remainingAttempts);
        return response;
    }

    /**
     * Compute a SHA-256 hex binding hash of the contact name, type and value. The serialized input is injective:
     * each field is prefixed with its UTF-8 byte length so that field boundaries are unambiguous and distinct inputs
     * cannot collide, i.e. {@code len(name):name:len(type):type:len(value):value}. The value is never logged or persisted.
     */
    private String computeBindingHash(String contactName, ContactType contactType, String contactValue) {
        final byte[] nameBytes = contactName.getBytes(StandardCharsets.UTF_8);
        final String typeName = contactType.name();
        final byte[] typeBytes = typeName.getBytes(StandardCharsets.UTF_8);
        final byte[] valueBytes = contactValue.getBytes(StandardCharsets.UTF_8);
        final String input = nameBytes.length + ":" + contactName + ":" + typeBytes.length + ":" + typeName + ":" + valueBytes.length + ":" + contactValue;
        try {
            final MessageDigest digest = MessageDigest.getInstance("SHA-256");
            final byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            final StringBuilder hex = new StringBuilder(hash.length * 2);
            for (byte b : hash) {
                hex.append(Character.forDigit((b >> 4) & 0xF, 16));
                hex.append(Character.forDigit(b & 0xF, 16));
            }
            return hex.toString();
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-256 algorithm is not available", ex);
        }
    }

    /**
     * Validate the caller-supplied deeplink base URL without building the final URL.
     */
    private void validateDeeplinkConfiguration(String baseUrl) throws InvalidRequestException {
        if (baseUrl == null) {
            throw new InvalidRequestException("Deeplink base URL is required for the DEEPLINK method");
        }
        validateDeeplinkUrl(baseUrl);
    }

    /**
     * Validate the optional caller-supplied message template. When present, it must contain the {@code {token}}
     * placeholder, otherwise the built deeplink would carry no token and the resulting verification could never be confirmed.
     */
    private void validateMessageTemplate(String messageTemplate) throws InvalidRequestException {
        if (messageTemplate != null && !messageTemplate.contains("{token}")) {
            throw new InvalidRequestException("Deeplink message template must contain the {token} placeholder");
        }
    }

    /**
     * Validate a deeplink URL: must be an absolute, parseable URI, must not use a dangerous non-navigational scheme, and
     * must satisfy the optional scheme/host allow-lists. Exception messages never echo the URL (it carries the OTP token).
     */
    private void validateDeeplinkUrl(String url) throws InvalidRequestException {
        final URI uri;
        try {
            uri = new URI(url);
        } catch (URISyntaxException ex) {
            throw new InvalidRequestException("Deeplink URL is not a valid URI");
        }
        if (uri.getScheme() == null) {
            throw new InvalidRequestException("Deeplink URL must be an absolute URI");
        }
        final String scheme = uri.getScheme().toLowerCase(Locale.ROOT);
        if (DANGEROUS_SCHEMES.contains(scheme)) {
            throw new InvalidRequestException("Deeplink URL uses a disallowed scheme");
        }
        if (!configuration.getAllowedUrlSchemes().isEmpty()
                && configuration.getAllowedUrlSchemes().stream().noneMatch(s -> s.equalsIgnoreCase(scheme))) {
            throw new InvalidRequestException("Deeplink URL scheme is not allowed");
        }
        if (("http".equals(scheme) || "https".equals(scheme))
                && !configuration.getAllowedUrlHosts().isEmpty()
                && configuration.getAllowedUrlHosts().stream().noneMatch(h -> h.equalsIgnoreCase(uri.getHost()))) {
            throw new InvalidRequestException("Deeplink URL host is not allowed");
        }
    }

    /**
     * Validate the deeplink base URL and build the final deeplink carrying the OTP value as the token.
     */
    private String buildDeeplink(String baseUrl, String messageTemplate, String otpValue) throws InvalidRequestException {
        validateDeeplinkConfiguration(baseUrl);
        final String finalUrl;
        if (messageTemplate != null) {
            finalUrl = messageTemplate.replace("{token}", otpValue);
        } else {
            // Insert the token query parameter before any URL fragment so a fragment is not corrupted
            // (e.g. https://ex.com/verify#frag must become https://ex.com/verify?token=...#frag).
            final int fragmentIndex = baseUrl.indexOf('#');
            final String beforeFragment = fragmentIndex >= 0 ? baseUrl.substring(0, fragmentIndex) : baseUrl;
            final String fragment = fragmentIndex >= 0 ? baseUrl.substring(fragmentIndex) : "";
            final String separator = beforeFragment.contains("?") ? "&" : "?";
            finalUrl = beforeFragment + separator + "token=" + otpValue + fragment;
        }
        // Validate the final URL too, so a messageTemplate cannot bypass the scheme/host guards.
        validateDeeplinkUrl(finalUrl);
        return finalUrl;
    }

}
