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
package com.wultra.security.powerauth.app.nextstep;

import com.wultra.security.powerauth.lib.nextstep.client.NextStepClientException;
import com.wultra.security.powerauth.lib.nextstep.model.entity.OtpGenerationParam;
import com.wultra.security.powerauth.lib.nextstep.model.entity.UserContactDetail;
import com.wultra.security.powerauth.lib.nextstep.model.entity.enumeration.ContactType;
import com.wultra.security.powerauth.lib.nextstep.model.entity.enumeration.ContactVerificationMethod;
import com.wultra.security.powerauth.lib.nextstep.model.enumeration.OtpGenerationAlgorithm;
import com.wultra.security.powerauth.lib.nextstep.model.exception.InvalidConfigurationException;
import com.wultra.security.powerauth.lib.nextstep.model.exception.InvalidRequestException;
import com.wultra.security.powerauth.lib.nextstep.model.exception.OtpDefinitionAlreadyExistsException;
import com.wultra.security.powerauth.lib.nextstep.model.exception.OtpDefinitionNotFoundException;
import com.wultra.security.powerauth.lib.nextstep.model.exception.OtpPolicyAlreadyExistsException;
import com.wultra.security.powerauth.lib.nextstep.model.exception.UserContactNotFoundException;
import com.wultra.security.powerauth.lib.nextstep.model.exception.UserNotFoundException;
import com.wultra.security.powerauth.lib.nextstep.model.request.ConfirmContactVerificationRequest;
import com.wultra.security.powerauth.lib.nextstep.model.request.CreateOtpDefinitionRequest;
import com.wultra.security.powerauth.lib.nextstep.model.request.CreateOtpPolicyRequest;
import com.wultra.security.powerauth.lib.nextstep.model.request.CreateUserRequest;
import com.wultra.security.powerauth.lib.nextstep.model.request.StartContactVerificationRequest;
import com.wultra.security.powerauth.lib.nextstep.model.request.UpdateOtpPolicyRequest;
import com.wultra.security.powerauth.lib.nextstep.model.response.CreateOtpResponse;
import com.wultra.security.powerauth.lib.nextstep.model.request.UpdateUserRequest;
import com.wultra.security.powerauth.lib.nextstep.model.response.ConfirmContactVerificationResponse;
import com.wultra.security.powerauth.lib.nextstep.model.response.StartContactVerificationResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Next Step contact verification flow tests (OTP).
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
class NextStepContactVerificationTest extends NextStepTest {

    private static final String OTP_DEFINITION = "CONTACT_VERIFICATION_OTP";
    private static final String DIGEST_OTP_DEFINITION = "CONTACT_VERIFICATION_DIGEST_OTP";
    private static final String OTP_DEFINITION_WITHOUT_EXPIRATION = "TEST_OTP";
    private static final String OTP_DEFINITION_WITHOUT_ATTEMPT_LIMIT = "CONTACT_VERIFICATION_NO_LIMIT_OTP";
    private static final String PROXY_OTP_DEFINITION = "CONTACT_VERIFICATION_PROXY_OTP";
    private static final String SHORT_LIVED_OTP_DEFINITION = "CONTACT_VERIFICATION_SHORT_LIVED_OTP";
    private static final String OTHER_CONTACT_NAME = "OTHER_CONTACT";
    private static final String CONTACT_NAME = "TEST_CONTACT";
    private static final ContactType CONTACT_TYPE = ContactType.EMAIL;

    @BeforeEach
    void setUp() throws Exception {
        nextStepClient = nextStepClientFactory.createNextStepClient("http://localhost:" + port);
        nextStepTestConfiguration.configure(nextStepClient);
        provisionOtpDefinition();
    }

    @Test
    void confirmsOtpVerification() throws NextStepClientException {
        final String userId = createUserWithContact("user@test.test");
        final StartContactVerificationResponse start = start(userId, OTP_DEFINITION);

        assertNotNull(start.getOtpValue());
        assertNotNull(start.getExpiresAt());
        assertTrue(start.getExpiresAt().after(new Date()));

        final ConfirmContactVerificationResponse confirm = confirm(userId, start.getVerificationId(), start.getOtpValue());

        assertTrue(confirm.isVerified());
        assertEquals(ContactVerificationMethod.OTP, confirm.getVerificationMethod());
        final UserContactDetail contact = singleContact(userId);
        assertEquals(ContactVerificationMethod.OTP, contact.getVerificationMethod());
        assertNotNull(contact.getTimestampVerified());
    }

    @Test
    void rejectsOtpReplayAfterSuccessfulConfirmation() throws NextStepClientException {
        final String userId = createUserWithContact("user@test.test");
        final StartContactVerificationResponse start = start(userId, OTP_DEFINITION);
        assertTrue(confirm(userId, start.getVerificationId(), start.getOtpValue()).isVerified());
        final Date timestampVerified = singleContact(userId).getTimestampVerified();

        final ConfirmContactVerificationResponse replay = confirm(userId, start.getVerificationId(), start.getOtpValue());

        assertFalse(replay.isVerified());
        assertEquals(timestampVerified, singleContact(userId).getTimestampVerified());
    }

    @Test
    void rejectsCorrectOtpAfterAttemptsExhausted() throws NextStepClientException {
        final String userId = createUserWithContact("user@test.test");
        final StartContactVerificationResponse start = start(userId, OTP_DEFINITION);

        assertEquals(Integer.valueOf(2), confirm(userId, start.getVerificationId(), "00000000").getRemainingAttempts());
        assertEquals(Integer.valueOf(1), confirm(userId, start.getVerificationId(), "00000000").getRemainingAttempts());
        assertEquals(Integer.valueOf(0), confirm(userId, start.getVerificationId(), "00000000").getRemainingAttempts());

        assertFalse(confirm(userId, start.getVerificationId(), start.getOtpValue()).isVerified());
        assertNull(singleContact(userId).getVerificationMethod());
    }

    @Test
    void rejectsWrongOtpValue() throws NextStepClientException {
        final String userId = createUserWithContact("user@test.test");
        final StartContactVerificationResponse start = start(userId, OTP_DEFINITION);

        final ConfirmContactVerificationResponse confirm = confirm(userId, start.getVerificationId(), "00000000");

        assertFalse(confirm.isVerified());
        assertNull(singleContact(userId).getVerificationMethod());
    }

    @Test
    void rejectsConfirmationAfterContactValueChange() throws NextStepClientException {
        final String userId = createUserWithContact("user@test.test");
        final StartContactVerificationResponse start = start(userId, OTP_DEFINITION);
        nextStepClient.updateUserContact(userId, CONTACT_NAME, CONTACT_TYPE, "changed@test.test", true);
        // Changing the value back must not revive the pending verification
        nextStepClient.updateUserContact(userId, CONTACT_NAME, CONTACT_TYPE, "user@test.test", true);

        final ConfirmContactVerificationResponse confirm = confirm(userId, start.getVerificationId(), start.getOtpValue());

        assertFalse(confirm.isVerified());
        assertNull(singleContact(userId).getVerificationMethod());
    }

    @Test
    void resetsVerificationWhenContactValueChanged() throws NextStepClientException {
        final String userId = createUserWithContact("user@test.test");
        final StartContactVerificationResponse start = start(userId, OTP_DEFINITION);
        assertTrue(confirm(userId, start.getVerificationId(), start.getOtpValue()).isVerified());

        nextStepClient.updateUserContact(userId, CONTACT_NAME, CONTACT_TYPE, "changed@test.test", true);

        final UserContactDetail contact = singleContact(userId);
        assertNull(contact.getVerificationMethod());
        assertNull(contact.getTimestampVerified());
    }

    @Test
    void resetsVerificationWhenContactValueChangedViaUserUpdate() throws NextStepClientException {
        final String userId = createUserWithContact("user@test.test");
        final StartContactVerificationResponse start = start(userId, OTP_DEFINITION);
        assertTrue(confirm(userId, start.getVerificationId(), start.getOtpValue()).isVerified());

        updateContactValueViaUserUpdate(userId, "changed@test.test");

        final UserContactDetail contact = singleContact(userId);
        assertNull(contact.getVerificationMethod());
        assertNull(contact.getTimestampVerified());
    }

    @Test
    void rejectsConfirmationAfterContactValueChangedAndRestoredViaUserUpdate() throws NextStepClientException {
        final String userId = createUserWithContact("user@test.test");
        final StartContactVerificationResponse start = start(userId, OTP_DEFINITION);
        updateContactValueViaUserUpdate(userId, "changed@test.test");
        // Changing the value back must not revive the pending verification
        updateContactValueViaUserUpdate(userId, "user@test.test");

        final ConfirmContactVerificationResponse confirm = confirm(userId, start.getVerificationId(), start.getOtpValue());

        assertFalse(confirm.isVerified());
        assertNull(singleContact(userId).getVerificationMethod());
    }

    @Test
    void resetsVerificationWhenContactTypeChangedViaUserUpdate() throws NextStepClientException {
        final String userId = createUserWithContact("user@test.test");
        final StartContactVerificationResponse start = start(userId, OTP_DEFINITION);
        assertTrue(confirm(userId, start.getVerificationId(), start.getOtpValue()).isVerified());

        updateContactViaUserUpdate(userId, ContactType.PHONE, "user@test.test");

        final UserContactDetail contact = singleContact(userId);
        assertNull(contact.getVerificationMethod());
        assertNull(contact.getTimestampVerified());
    }

    @Test
    void rejectsConfirmationAfterContactTypeChangedAndRestoredViaUserUpdate() throws NextStepClientException {
        final String userId = createUserWithContact("user@test.test");
        final StartContactVerificationResponse start = start(userId, OTP_DEFINITION);
        updateContactViaUserUpdate(userId, ContactType.PHONE, "user@test.test");
        // Changing the type back must not revive the pending verification
        updateContactViaUserUpdate(userId, CONTACT_TYPE, "user@test.test");

        final ConfirmContactVerificationResponse confirm = confirm(userId, start.getVerificationId(), start.getOtpValue());

        assertFalse(confirm.isVerified());
        assertNull(singleContact(userId).getVerificationMethod());
    }

    @Test
    void rejectsConfirmationAfterContactRemovedAndRecreatedViaUserUpdate() throws NextStepClientException {
        final String userId = createUserWithContact("user@test.test");
        final StartContactVerificationResponse start = start(userId, OTP_DEFINITION);
        final UpdateUserRequest request = new UpdateUserRequest();
        request.setUserId(userId);
        request.setContacts(List.of());
        nextStepClient.updateUser(request);
        // Same name, type and value yields the same binding hash, so only invalidation on removal blocks the old OTP
        nextStepClient.createUserContact(userId, CONTACT_NAME, CONTACT_TYPE, "user@test.test", true);

        final ConfirmContactVerificationResponse confirm = confirm(userId, start.getVerificationId(), start.getOtpValue());

        assertFalse(confirm.isVerified());
        assertNull(singleContact(userId).getVerificationMethod());
    }

    @Test
    void rejectsVerificationOtpOnGenericOtpAuthentication() throws NextStepClientException {
        final String userId = createUserWithContact("user@test.test");
        final StartContactVerificationResponse start = start(userId, OTP_DEFINITION);

        final NextStepClientException ex = assertThrows(NextStepClientException.class,
                () -> nextStepClient.authenticateWithOtp(start.getVerificationId(), start.getOtpValue()));

        assertEquals(InvalidRequestException.CODE, ex.getError().getCode());
        // The OTP is not consumed by the rejected call
        assertTrue(confirm(userId, start.getVerificationId(), start.getOtpValue()).isVerified());
    }

    @Test
    void rejectsVerificationOtpOnCombinedAuthentication() throws NextStepClientException {
        final String userId = createUserWithContact("user@test.test");
        final StartContactVerificationResponse start = start(userId, OTP_DEFINITION);

        final NextStepClientException ex = assertThrows(NextStepClientException.class,
                () -> nextStepClient.authenticateCombined(userId, "credential", start.getVerificationId(), start.getOtpValue()));

        assertEquals(InvalidRequestException.CODE, ex.getError().getCode());
        assertTrue(ex.getError().getMessage().contains("Contact verification OTP"));
        assertTrue(confirm(userId, start.getVerificationId(), start.getOtpValue()).isVerified());
    }

    @Test
    void rejectsConfirmationAfterContactDeletedAndRecreated() throws NextStepClientException {
        final String userId = createUserWithContact("user@test.test");
        final StartContactVerificationResponse start = start(userId, OTP_DEFINITION);
        nextStepClient.deleteUserContact(userId, CONTACT_NAME, CONTACT_TYPE);
        // Same name, type and value yields the same binding hash, so only invalidation on deletion blocks the old OTP
        nextStepClient.createUserContact(userId, CONTACT_NAME, CONTACT_TYPE, "user@test.test", true);

        final ConfirmContactVerificationResponse confirm = confirm(userId, start.getVerificationId(), start.getOtpValue());

        assertFalse(confirm.isVerified());
        assertNull(singleContact(userId).getVerificationMethod());
    }

    @Test
    void confirmsOtpVerificationWithDigestAlgorithm() throws NextStepClientException {
        final String userId = createUserWithContact("user@test.test");
        final StartContactVerificationResponse start = start(userId, DIGEST_OTP_DEFINITION);

        assertTrue(confirm(userId, start.getVerificationId(), start.getOtpValue()).isVerified());
        assertEquals(ContactVerificationMethod.OTP, singleContact(userId).getVerificationMethod());
    }

    @Test
    void rejectsOtpDefinitionWithoutExpirationTime() throws NextStepClientException {
        final String userId = createUserWithContact("user@test.test");

        assertStartFails(userId, CONTACT_NAME, OTP_DEFINITION_WITHOUT_EXPIRATION, InvalidConfigurationException.CODE);
    }

    @Test
    void invalidatesPreviousOtpWhenVerificationRestarted() throws NextStepClientException {
        final String userId = createUserWithContact("user@test.test");
        final StartContactVerificationResponse first = start(userId, OTP_DEFINITION);
        final StartContactVerificationResponse second = start(userId, OTP_DEFINITION);

        assertFalse(confirm(userId, first.getVerificationId(), first.getOtpValue()).isVerified());
        assertTrue(confirm(userId, second.getVerificationId(), second.getOtpValue()).isVerified());
    }

    @Test
    void invalidatesPendingOtpOfOtherContactWhenVerificationStarted() throws NextStepClientException {
        final String userId = createUserWithContact("user@test.test");
        nextStepClient.createUserContact(userId, OTHER_CONTACT_NAME, CONTACT_TYPE, "other@test.test", false);
        final StartContactVerificationResponse first = start(userId, CONTACT_NAME, OTP_DEFINITION);
        start(userId, OTHER_CONTACT_NAME, OTP_DEFINITION);

        assertFalse(confirm(userId, CONTACT_NAME, first.getVerificationId(), first.getOtpValue()).isVerified());
        assertNull(singleContact(userId).getVerificationMethod());
    }

    @Test
    void invalidatesPendingOtpOfOtherContactWhenContactValueChanged() throws NextStepClientException {
        final String userId = createUserWithContact("user@test.test");
        nextStepClient.createUserContact(userId, OTHER_CONTACT_NAME, CONTACT_TYPE, "other@test.test", false);
        final StartContactVerificationResponse pending = start(userId, OTHER_CONTACT_NAME, OTP_DEFINITION);
        nextStepClient.updateUserContact(userId, CONTACT_NAME, CONTACT_TYPE, "changed@test.test", true);

        assertFalse(confirm(userId, OTHER_CONTACT_NAME, pending.getVerificationId(), pending.getOtpValue()).isVerified());
        assertTrue(nextStepClient.getUserContactList(userId).getResponseObject().getContacts().stream()
                .allMatch(c -> c.getVerificationMethod() == null));
    }

    @Test
    void invalidatesPendingOtpOfOtherContactWhenContactDeleted() throws NextStepClientException {
        final String userId = createUserWithContact("user@test.test");
        nextStepClient.createUserContact(userId, OTHER_CONTACT_NAME, CONTACT_TYPE, "other@test.test", false);
        final StartContactVerificationResponse pending = start(userId, OTHER_CONTACT_NAME, OTP_DEFINITION);
        nextStepClient.deleteUserContact(userId, CONTACT_NAME, CONTACT_TYPE);

        assertFalse(confirm(userId, OTHER_CONTACT_NAME, pending.getVerificationId(), pending.getOtpValue()).isVerified());
        assertTrue(nextStepClient.getUserContactList(userId).getResponseObject().getContacts().stream()
                .allMatch(c -> c.getVerificationMethod() == null));
    }

    @Test
    void rejectsConfirmationWithoutStartedVerification() throws NextStepClientException {
        final String userId = createUserWithContact("user@test.test");

        final ConfirmContactVerificationResponse confirm = confirm(userId, UUID.randomUUID().toString(), "12345678");

        assertFalse(confirm.isVerified());
        assertNull(singleContact(userId).getVerificationMethod());
    }

    @Test
    void rejectsOtpDefinitionWithoutAttemptLimit() throws NextStepClientException {
        final String userId = createUserWithContact("user@test.test");

        assertStartFails(userId, CONTACT_NAME, OTP_DEFINITION_WITHOUT_ATTEMPT_LIMIT, InvalidConfigurationException.CODE);
    }

    @Test
    void rejectsDataAdapterProxyOtpDefinition() throws NextStepClientException {
        final String userId = createUserWithContact("user@test.test");

        assertStartFails(userId, CONTACT_NAME, PROXY_OTP_DEFINITION, InvalidConfigurationException.CODE);
    }

    @Test
    void rejectsStartForUnknownUserContactOrDefinition() throws NextStepClientException {
        final String userId = createUserWithContact("user@test.test");

        assertStartFails(UUID.randomUUID().toString(), CONTACT_NAME, OTP_DEFINITION, UserNotFoundException.CODE);
        assertStartFails(userId, "UNKNOWN_CONTACT", OTP_DEFINITION, UserContactNotFoundException.CODE);
        assertStartFails(userId, CONTACT_NAME, "UNKNOWN_DEFINITION", OtpDefinitionNotFoundException.CODE);
    }

    @Test
    void rejectsConfirmationOfExpiredOtp() throws Exception {
        final String userId = createUserWithContact("user@test.test");
        final StartContactVerificationResponse start = start(userId, SHORT_LIVED_OTP_DEFINITION);
        Thread.sleep(2_000);

        assertFalse(confirm(userId, start.getVerificationId(), start.getOtpValue()).isVerified());
        assertNull(singleContact(userId).getVerificationMethod());
    }

    @Test
    void rejectsOtpIssuedForContactWithAmbiguousBindingInput() throws NextStepClientException {
        final String userId = createUserWithContact("user@test.test");
        // Joined with a plain colon, both contacts would serialize to "AB:EMAIL:x:PHONE:yy"
        nextStepClient.createUserContact(userId, "AB", ContactType.EMAIL, "x:PHONE:yy", false);
        nextStepClient.createUserContact(userId, "AB:EMAIL:x", ContactType.PHONE, "yy", false);
        final StartContactVerificationResponse start = start(userId, "AB", ContactType.EMAIL, OTP_DEFINITION);

        final ConfirmContactVerificationResponse confirm = confirm(userId, "AB:EMAIL:x", ContactType.PHONE, start.getVerificationId(), start.getOtpValue());

        assertFalse(confirm.isVerified());
    }

    @Test
    void rejectsOtpIssuedForDifferentContact() throws NextStepClientException {
        final String userId = createUserWithContact("user@test.test");
        nextStepClient.createUserContact(userId, OTHER_CONTACT_NAME, CONTACT_TYPE, "other@test.test", false);
        final StartContactVerificationResponse start = start(userId, CONTACT_NAME, OTP_DEFINITION);

        final ConfirmContactVerificationResponse confirm = confirm(userId, OTHER_CONTACT_NAME, start.getVerificationId(), start.getOtpValue());

        assertFalse(confirm.isVerified());
        assertTrue(nextStepClient.getUserContactList(userId).getResponseObject().getContacts().stream()
                .allMatch(c -> c.getVerificationMethod() == null));
    }

    @Test
    void rejectsOtpIssuedForDifferentUser() throws NextStepClientException {
        final String userId = createUserWithContact("user@test.test");
        final String otherUserId = createUserWithContact("user@test.test");
        final StartContactVerificationResponse start = start(userId, OTP_DEFINITION);

        assertFalse(confirm(otherUserId, start.getVerificationId(), start.getOtpValue()).isVerified());
        assertNull(singleContact(otherUserId).getVerificationMethod());
    }

    @Test
    void returnsFailedForMissingUserOrContact() throws NextStepClientException {
        final String userWithContact = createUserWithContact("contact@test.test");
        final StartContactVerificationResponse contactVerification = start(userWithContact, OTP_DEFINITION);
        nextStepClient.deleteUserContact(userWithContact, CONTACT_NAME, CONTACT_TYPE);
        assertFalse(confirm(userWithContact, contactVerification.getVerificationId(), contactVerification.getOtpValue()).isVerified());

        final String deletedUser = createUserWithContact("deleted@test.test");
        final StartContactVerificationResponse userVerification = start(deletedUser, OTP_DEFINITION);
        nextStepClient.deleteUser(deletedUser);
        assertFalse(confirm(deletedUser, userVerification.getVerificationId(), userVerification.getOtpValue()).isVerified());
    }

    @Test
    void rejectsConfirmationForBlockedUser() throws NextStepClientException {
        final String userId = createUserWithContact("user@test.test");
        final StartContactVerificationResponse start = start(userId, OTP_DEFINITION);
        nextStepClient.blockUser(userId);

        assertFalse(confirm(userId, start.getVerificationId(), start.getOtpValue()).isVerified());
        assertNull(singleContact(userId).getVerificationMethod());
    }

    @Test
    void rejectsConfirmationAfterAttemptLimitRemovedFromPolicy() throws NextStepClientException {
        final String suffix = UUID.randomUUID().toString().substring(0, 8);
        final CreateOtpPolicyRequest policy = new CreateOtpPolicyRequest();
        policy.setOtpPolicyName("CV_MUTABLE_POLICY_" + suffix);
        policy.setAttemptLimit(3);
        policy.setLength(8);
        policy.setExpirationTime(300L);
        policy.setGenAlgorithm(OtpGenerationAlgorithm.OTP_RANDOM_DIGIT_GROUPS);
        final OtpGenerationParam genParam = new OtpGenerationParam();
        genParam.setGroupSize(2);
        policy.setGenParam(genParam);
        final CreateOtpDefinitionRequest definition = new CreateOtpDefinitionRequest();
        definition.setOtpDefinitionName("CV_MUTABLE_OTP_" + suffix);
        definition.setApplicationName("TEST_APP");
        definition.setOtpPolicyName(policy.getOtpPolicyName());
        createPolicyAndDefinition(policy, definition);
        final String userId = createUserWithContact("user@test.test");
        final StartContactVerificationResponse start = start(userId, definition.getOtpDefinitionName());

        final UpdateOtpPolicyRequest update = new UpdateOtpPolicyRequest();
        update.setOtpPolicyName(policy.getOtpPolicyName());
        update.setLength(8);
        update.setExpirationTime(300L);
        nextStepClient.updateOtpPolicy(update);

        assertFalse(confirm(userId, start.getVerificationId(), start.getOtpValue()).isVerified());
        assertNull(singleContact(userId).getVerificationMethod());
    }

    @Test
    void rejectsGenericOtpWithMatchingBindingHash() throws NextStepClientException {
        final String userId = createUserWithContact("user@test.test");
        final CreateOtpResponse generic = nextStepClient.createOtp(userId, OTP_DEFINITION, null,
                bindingHash(CONTACT_NAME, CONTACT_TYPE, "user@test.test")).getResponseObject();

        assertFalse(confirm(userId, generic.getOtpId(), generic.getOtpValue()).isVerified());
        assertNull(singleContact(userId).getVerificationMethod());
    }

    // Mirrors the production binding hash: SHA-256 over length-prefixed name, type and value, Base64 encoded.
    private static String bindingHash(final String name, final ContactType type, final String value) {
        try {
            final MessageDigest md = MessageDigest.getInstance("SHA-256");
            for (final String field : List.of(name, type.name(), value)) {
                final byte[] bytes = field.getBytes(StandardCharsets.UTF_8);
                md.update(ByteBuffer.allocate(Integer.BYTES).putInt(bytes.length).array());
                md.update(bytes);
            }
            return Base64.getEncoder().encodeToString(md.digest());
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException(ex);
        }
    }

    private StartContactVerificationResponse start(final String userId, final String otpDefinitionName) throws NextStepClientException {
        return start(userId, CONTACT_NAME, otpDefinitionName);
    }

    private StartContactVerificationResponse start(final String userId, final String contactName, final String otpDefinitionName) throws NextStepClientException {
        return start(userId, contactName, CONTACT_TYPE, otpDefinitionName);
    }

    private StartContactVerificationResponse start(final String userId, final String contactName, final ContactType contactType,
                                                   final String otpDefinitionName) throws NextStepClientException {
        final StartContactVerificationRequest request = new StartContactVerificationRequest();
        request.setUserId(userId);
        request.setContactName(contactName);
        request.setContactType(contactType);
        request.setOtpDefinitionName(otpDefinitionName);
        return nextStepClient.startContactVerification(request).getResponseObject();
    }

    private void assertStartFails(final String userId, final String contactName, final String otpDefinitionName,
                                  final String errorCode) {
        final NextStepClientException ex = assertThrows(NextStepClientException.class, () -> start(userId, contactName, otpDefinitionName));

        assertEquals(errorCode, ex.getError().getCode());
    }

    private ConfirmContactVerificationResponse confirm(final String userId, final String verificationId,
                                                       final String otpValue) throws NextStepClientException {
        return confirm(userId, CONTACT_NAME, verificationId, otpValue);
    }

    private ConfirmContactVerificationResponse confirm(final String userId, final String contactName, final String verificationId,
                                                       final String otpValue) throws NextStepClientException {
        return confirm(userId, contactName, CONTACT_TYPE, verificationId, otpValue);
    }

    private ConfirmContactVerificationResponse confirm(final String userId, final String contactName, final ContactType contactType,
                                                       final String verificationId, final String otpValue) throws NextStepClientException {
        final ConfirmContactVerificationRequest request = new ConfirmContactVerificationRequest();
        request.setUserId(userId);
        request.setContactName(contactName);
        request.setContactType(contactType);
        request.setVerificationId(verificationId);
        request.setOtpValue(otpValue);
        return nextStepClient.confirmContactVerification(request).getResponseObject();
    }

    private void updateContactValueViaUserUpdate(final String userId, final String value) throws NextStepClientException {
        updateContactViaUserUpdate(userId, CONTACT_TYPE, value);
    }

    private void updateContactViaUserUpdate(final String userId, final ContactType type, final String value) throws NextStepClientException {
        final UpdateUserRequest.UpdatedContact contact = new UpdateUserRequest.UpdatedContact();
        contact.setContactName(CONTACT_NAME);
        contact.setContactType(type);
        contact.setContactValue(value);
        contact.setPrimary(true);
        final UpdateUserRequest request = new UpdateUserRequest();
        request.setUserId(userId);
        request.setContacts(List.of(contact));
        nextStepClient.updateUser(request);
    }

    private String createUserWithContact(final String value) throws NextStepClientException {
        final String userId = UUID.randomUUID().toString();
        final CreateUserRequest request = new CreateUserRequest();
        request.setUserId(userId);
        nextStepClient.createUser(request);
        nextStepClient.createUserContact(userId, CONTACT_NAME, CONTACT_TYPE, value, true);
        return userId;
    }

    private UserContactDetail singleContact(final String userId) throws NextStepClientException {
        return nextStepClient.getUserContactList(userId).getResponseObject().getContacts().stream()
                .filter(c -> CONTACT_NAME.equals(c.getContactName()))
                .findFirst()
                .orElseThrow();
    }

    private void provisionOtpDefinition() throws NextStepClientException {
        final OtpGenerationParam genParam = new OtpGenerationParam();
        genParam.setGroupSize(2);
        final CreateOtpPolicyRequest policy = new CreateOtpPolicyRequest();
        policy.setOtpPolicyName("CONTACT_VERIFICATION_OTP_POLICY");
        policy.setAttemptLimit(3);
        policy.setLength(8);
        policy.setExpirationTime(300L);
        policy.setGenAlgorithm(OtpGenerationAlgorithm.OTP_RANDOM_DIGIT_GROUPS);
        policy.setGenParam(genParam);
        final CreateOtpDefinitionRequest definition = new CreateOtpDefinitionRequest();
        definition.setOtpDefinitionName(OTP_DEFINITION);
        definition.setApplicationName("TEST_APP");
        definition.setOtpPolicyName(policy.getOtpPolicyName());
        createPolicyAndDefinition(policy, definition);

        final CreateOtpPolicyRequest digestPolicy = new CreateOtpPolicyRequest();
        digestPolicy.setOtpPolicyName("CONTACT_VERIFICATION_DIGEST_OTP_POLICY");
        digestPolicy.setAttemptLimit(3);
        digestPolicy.setLength(8);
        digestPolicy.setExpirationTime(300L);
        digestPolicy.setGenAlgorithm(OtpGenerationAlgorithm.OTP_DATA_DIGEST);
        final CreateOtpDefinitionRequest digestDefinition = new CreateOtpDefinitionRequest();
        digestDefinition.setOtpDefinitionName(DIGEST_OTP_DEFINITION);
        digestDefinition.setApplicationName("TEST_APP");
        digestDefinition.setOtpPolicyName(digestPolicy.getOtpPolicyName());
        createPolicyAndDefinition(digestPolicy, digestDefinition);

        final CreateOtpPolicyRequest noLimitPolicy = new CreateOtpPolicyRequest();
        noLimitPolicy.setOtpPolicyName("CONTACT_VERIFICATION_NO_LIMIT_OTP_POLICY");
        noLimitPolicy.setLength(8);
        noLimitPolicy.setExpirationTime(300L);
        noLimitPolicy.setGenAlgorithm(OtpGenerationAlgorithm.OTP_RANDOM_DIGIT_GROUPS);
        noLimitPolicy.setGenParam(genParam);
        final CreateOtpDefinitionRequest noLimitDefinition = new CreateOtpDefinitionRequest();
        noLimitDefinition.setOtpDefinitionName(OTP_DEFINITION_WITHOUT_ATTEMPT_LIMIT);
        noLimitDefinition.setApplicationName("TEST_APP");
        noLimitDefinition.setOtpPolicyName(noLimitPolicy.getOtpPolicyName());
        createPolicyAndDefinition(noLimitPolicy, noLimitDefinition);

        final CreateOtpDefinitionRequest proxyDefinition = new CreateOtpDefinitionRequest();
        proxyDefinition.setOtpDefinitionName(PROXY_OTP_DEFINITION);
        proxyDefinition.setApplicationName("TEST_APP");
        proxyDefinition.setOtpPolicyName(policy.getOtpPolicyName());
        proxyDefinition.setDataAdapterProxyEnabled(true);
        createPolicyAndDefinition(policy, proxyDefinition);

        final CreateOtpPolicyRequest shortLivedPolicy = new CreateOtpPolicyRequest();
        shortLivedPolicy.setOtpPolicyName("CONTACT_VERIFICATION_SHORT_LIVED_OTP_POLICY");
        shortLivedPolicy.setAttemptLimit(3);
        shortLivedPolicy.setLength(8);
        shortLivedPolicy.setExpirationTime(1L);
        shortLivedPolicy.setGenAlgorithm(OtpGenerationAlgorithm.OTP_RANDOM_DIGIT_GROUPS);
        shortLivedPolicy.setGenParam(genParam);
        final CreateOtpDefinitionRequest shortLivedDefinition = new CreateOtpDefinitionRequest();
        shortLivedDefinition.setOtpDefinitionName(SHORT_LIVED_OTP_DEFINITION);
        shortLivedDefinition.setApplicationName("TEST_APP");
        shortLivedDefinition.setOtpPolicyName(shortLivedPolicy.getOtpPolicyName());
        createPolicyAndDefinition(shortLivedPolicy, shortLivedDefinition);
    }

    private void createPolicyAndDefinition(final CreateOtpPolicyRequest policy, final CreateOtpDefinitionRequest definition) throws NextStepClientException {
        try {
            nextStepClient.createOtpPolicy(policy);
        } catch (NextStepClientException ex) {
            rethrowUnlessAlreadyExists(ex, OtpPolicyAlreadyExistsException.CODE);
        }
        try {
            nextStepClient.createOtpDefinition(definition);
        } catch (NextStepClientException ex) {
            rethrowUnlessAlreadyExists(ex, OtpDefinitionAlreadyExistsException.CODE);
        }
    }

    // The Spring context is shared, so an earlier test may have provisioned the definition. Any other failure must surface.
    private void rethrowUnlessAlreadyExists(final NextStepClientException ex, final String alreadyExistsCode) throws NextStepClientException {
        if (!alreadyExistsCode.equals(ex.getError().getCode())) {
            throw ex;
        }
    }

}
