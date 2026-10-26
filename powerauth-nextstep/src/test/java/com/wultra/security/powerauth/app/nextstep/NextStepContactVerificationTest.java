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

import com.wultra.security.powerauth.app.nextstep.configuration.ContactVerificationConfiguration;
import com.wultra.security.powerauth.lib.nextstep.client.NextStepClientException;
import com.wultra.security.powerauth.lib.nextstep.model.entity.OtpGenerationParam;
import com.wultra.security.powerauth.lib.nextstep.model.entity.UserContactDetail;
import com.wultra.security.powerauth.lib.nextstep.model.entity.enumeration.ContactType;
import com.wultra.security.powerauth.lib.nextstep.model.entity.enumeration.ContactVerificationMethod;
import com.wultra.security.powerauth.lib.nextstep.model.entity.enumeration.OtpStatus;
import com.wultra.security.powerauth.lib.nextstep.model.enumeration.OtpGenerationAlgorithm;
import com.wultra.security.powerauth.lib.nextstep.model.exception.InvalidConfigurationException;
import com.wultra.security.powerauth.lib.nextstep.model.exception.InvalidRequestException;
import com.wultra.security.powerauth.lib.nextstep.model.exception.UserContactNotFoundException;
import com.wultra.security.powerauth.lib.nextstep.model.exception.UserNotFoundException;
import com.wultra.security.powerauth.lib.nextstep.model.request.CreateOtpDefinitionRequest;
import com.wultra.security.powerauth.lib.nextstep.model.request.CreateOtpPolicyRequest;
import com.wultra.security.powerauth.lib.nextstep.model.request.CreateUserRequest;
import com.wultra.security.powerauth.lib.nextstep.model.request.UpdateOtpPolicyRequest;
import com.wultra.security.powerauth.lib.nextstep.model.request.UpdateUserRequest;
import com.wultra.security.powerauth.lib.nextstep.model.response.ConfirmContactVerificationResponse;
import com.wultra.security.powerauth.lib.nextstep.model.response.StartContactVerificationResponse;
import com.wultra.security.powerauth.lib.nextstep.model.response.UpdateUserResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Next Step contact verification flow tests (OTP and deeplink).
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
class NextStepContactVerificationTest extends NextStepTest {

    private static final String OTP_DEFINITION = "CONTACT_VERIFICATION_OTP";
    private static final String DIGEST_OTP_DEFINITION = "TEST_OTP";
    private static final String NO_LIMIT_OTP_DEFINITION = "CONTACT_VERIFICATION_NO_LIMIT_OTP";
    private static final String NO_EXPIRY_OTP_DEFINITION = "CONTACT_VERIFICATION_NO_EXPIRY_OTP";
    private static final String EXPIRING_OTP_DEFINITION = "CONTACT_VERIFICATION_EXPIRING_OTP";
    private static final String MUTABLE_OTP_DEFINITION = "CONTACT_VERIFICATION_MUTABLE_OTP";
    private static final String MUTABLE_OTP_POLICY = "CONTACT_VERIFICATION_MUTABLE_POLICY";
    private static final String CONTACT_NAME = "TEST_CONTACT";
    private static final ContactType CONTACT_TYPE = ContactType.EMAIL;

    @Autowired
    private ContactVerificationConfiguration contactVerificationConfiguration;

    @BeforeEach
    void setUp() throws Exception {
        nextStepClient = nextStepClientFactory.createNextStepClient("http://localhost:" + port);
        nextStepTestConfiguration.configure(nextStepClient);
        ensureVerificationOtpDefinition();
        // Ensure allow-lists never leak between tests that mutate them.
        contactVerificationConfiguration.setAllowedUrlHosts(new java.util.ArrayList<>());
        contactVerificationConfiguration.setAllowedUrlSchemes(new java.util.ArrayList<>());
    }

    @Test
    void startsOtpVerificationForExistingContact() throws NextStepClientException {
        final String userId = createUserWithContact("user@test.test");

        final StartContactVerificationResponse response = startOtp(userId);

        assertNotNull(response.getVerificationId());
        assertEquals(ContactVerificationMethod.OTP, response.getMethod());
        assertNotNull(response.getOtpValue());
        assertNull(response.getDeeplinkUrl());
        assertNotNull(response.getExpiresAt());
        assertTrue(response.getExpiresAt().after(new Date()));
        assertEquals("user@test.test", response.getContactValue());
    }

    @Test
    void confirmsOtpVerificationWithCorrectValue() throws NextStepClientException {
        final String userId = createUserWithContact("user@test.test");
        final StartContactVerificationResponse start = startOtp(userId);

        final ConfirmContactVerificationResponse confirm =
                confirm(userId, CONTACT_NAME, start.getVerificationId(), start.getOtpValue(), null);

        assertTrue(confirm.isVerified());
        assertEquals(ContactVerificationMethod.OTP, confirm.getVerificationMethod());

        final UserContactDetail contact = singleContact(userId);
        assertEquals(ContactVerificationMethod.OTP, contact.getVerificationMethod());
        assertNotNull(contact.getTimestampVerified());
    }

    @Test
    void rejectsOtpConfirmationWithWrongValue() throws NextStepClientException {
        final String userId = createUserWithContact("user@test.test");
        final StartContactVerificationResponse start = startOtp(userId);

        final ConfirmContactVerificationResponse confirm =
                confirm(userId, CONTACT_NAME, start.getVerificationId(), "00000000", null);

        assertFalse(confirm.isVerified());
        assertNull(confirm.getRemainingAttempts());
        assertNull(singleContact(userId).getVerificationMethod());
    }

    @Test
    void blocksOtpAfterReachingAttemptLimit() throws NextStepClientException {
        final String userId = createUserWithContact("user@test.test");
        final StartContactVerificationResponse start = startOtp(userId);

        for (int i = 0; i < 3; i++) {
            confirm(userId, CONTACT_NAME, start.getVerificationId(), "00000000", null);
        }
        // Even the correct value must no longer verify once the attempt limit has been reached.
        final ConfirmContactVerificationResponse confirm =
                confirm(userId, CONTACT_NAME, start.getVerificationId(), start.getOtpValue(), null);

        assertFalse(confirm.isVerified());
        assertNull(singleContact(userId).getVerificationMethod());
    }

    @Test
    void keepsOnlyLatestVerificationActiveAfterRestart() throws NextStepClientException {
        final String userId = createUserWithContact("user@test.test");
        final StartContactVerificationResponse first = startOtp(userId);
        final StartContactVerificationResponse second = startOtp(userId);

        final ConfirmContactVerificationResponse staleConfirm =
                confirm(userId, CONTACT_NAME, first.getVerificationId(), first.getOtpValue(), null);
        assertFalse(staleConfirm.isVerified());

        final ConfirmContactVerificationResponse latestConfirm =
                confirm(userId, CONTACT_NAME, second.getVerificationId(), second.getOtpValue(), null);
        assertTrue(latestConfirm.isVerified());
    }

    @Test
    void rejectsOtpConfirmationAfterContactValueChangedAndDoesNotReviveOnChangeBack() throws NextStepClientException {
        final String userId = createUserWithContact("user@test.test");
        final StartContactVerificationResponse start = startOtp(userId);

        // Value A -> B: the OTP bound to A no longer matches the current value and must not confirm.
        nextStepClient.updateUserContact(userId, CONTACT_NAME, CONTACT_TYPE, "changed@test.test", false);
        assertFalse(confirm(userId, CONTACT_NAME, start.getVerificationId(), start.getOtpValue(), null).isVerified());

        // Value B -> A: even though the current value matches the OTP binding again, the pending OTP was invalidated
        // on the first change and must not be revived.
        nextStepClient.updateUserContact(userId, CONTACT_NAME, CONTACT_TYPE, "user@test.test", false);
        assertFalse(confirm(userId, CONTACT_NAME, start.getVerificationId(), start.getOtpValue(), null).isVerified());
        assertNull(singleContact(userId).getVerificationMethod());
    }

    @Test
    void rejectsOtpConfirmationForWrongContact() throws NextStepClientException {
        final String userId = createUserWithContact("user@test.test");
        nextStepClient.createUserContact(userId, "OTHER_CONTACT", CONTACT_TYPE, "other@test.test", false);
        final StartContactVerificationResponse start = startOtp(userId);

        // Same user and a real contact, but not the one the OTP was bound to -> generic failure, not an exception.
        final ConfirmContactVerificationResponse confirm =
                confirm(userId, "OTHER_CONTACT", start.getVerificationId(), start.getOtpValue(), null);

        assertFalse(confirm.isVerified());
        assertNull(singleContact(userId, "OTHER_CONTACT").getVerificationMethod());
    }

    @Test
    void failsToStartVerificationForMissingContact() {
        final String userId = UUID.randomUUID().toString();
        try {
            nextStepClient.createUser(newUserRequest(userId));
        } catch (NextStepClientException ex) {
            fail(ex);
        }

        final NextStepClientException thrown = assertThrows(NextStepClientException.class,
                () -> nextStepClient.startContactVerification(userId, CONTACT_NAME, CONTACT_TYPE,
                        ContactVerificationMethod.OTP, OTP_DEFINITION));
        assertEquals(UserContactNotFoundException.CODE, thrown.getError().getCode());
    }

    @Test
    void confirmsDeeplinkVerificationWithToken() throws NextStepClientException {
        final String userId = createUserWithContact("user@test.test");

        final StartContactVerificationResponse start = startDeeplink(userId, "https://example.com/verify");
        assertEquals(ContactVerificationMethod.DEEPLINK, start.getMethod());
        assertNull(start.getOtpValue());
        assertNotNull(start.getDeeplinkUrl());
        assertTrue(start.getDeeplinkUrl().contains("token="));

        final String token = extractToken(start.getDeeplinkUrl());
        final ConfirmContactVerificationResponse confirm =
                confirm(userId, CONTACT_NAME, start.getVerificationId(), null, token);

        assertTrue(confirm.isVerified());
        assertEquals(ContactVerificationMethod.DEEPLINK, confirm.getVerificationMethod());
        assertEquals(ContactVerificationMethod.DEEPLINK, singleContact(userId).getVerificationMethod());
    }

    @Test
    void rejectsDeeplinkWithDangerousScheme() throws NextStepClientException {
        final String userId = createUserWithContact("user@test.test");

        final NextStepClientException thrown = assertThrows(NextStepClientException.class,
                () -> startDeeplink(userId, "javascript:alert(1)"));
        assertEquals(InvalidRequestException.CODE, thrown.getError().getCode());
    }

    @Test
    void rejectsOtpVerificationConfirmedWithTokenButSucceedsWithOtpValue() throws NextStepClientException {
        final String userId = createUserWithContact("user@test.test");
        final StartContactVerificationResponse start = startOtp(userId);

        // Wrong channel: supplying the credential as a token for an OTP-method verification must fail generically
        // and must not consume an attempt (the guard returns before authentication).
        final ConfirmContactVerificationResponse wrongChannel =
                confirm(userId, CONTACT_NAME, start.getVerificationId(), null, start.getOtpValue());
        assertFalse(wrongChannel.isVerified());
        assertNull(wrongChannel.getRemainingAttempts());
        assertNull(singleContact(userId).getVerificationMethod());

        // The same verification still confirms with the correct channel, proving the OTP was not consumed or broken.
        final ConfirmContactVerificationResponse correctChannel =
                confirm(userId, CONTACT_NAME, start.getVerificationId(), start.getOtpValue(), null);
        assertTrue(correctChannel.isVerified());
        assertEquals(ContactVerificationMethod.OTP, correctChannel.getVerificationMethod());
        assertEquals(ContactVerificationMethod.OTP, singleContact(userId).getVerificationMethod());
    }

    @Test
    void rejectsDeeplinkVerificationConfirmedWithOtpValueButSucceedsWithToken() throws NextStepClientException {
        final String userId = createUserWithContact("user@test.test");
        final StartContactVerificationResponse start = startDeeplink(userId, "https://example.com/verify");
        final String token = extractToken(start.getDeeplinkUrl());

        // Wrong channel: supplying the credential as an otpValue for a DEEPLINK-method verification must fail generically.
        final ConfirmContactVerificationResponse wrongChannel =
                confirm(userId, CONTACT_NAME, start.getVerificationId(), token, null);
        assertFalse(wrongChannel.isVerified());
        assertNull(singleContact(userId).getVerificationMethod());

        final ConfirmContactVerificationResponse correctChannel =
                confirm(userId, CONTACT_NAME, start.getVerificationId(), null, token);
        assertTrue(correctChannel.isVerified());
        assertEquals(ContactVerificationMethod.DEEPLINK, correctChannel.getVerificationMethod());
        assertEquals(ContactVerificationMethod.DEEPLINK, singleContact(userId).getVerificationMethod());
    }

    @Test
    void rejectsConfirmationOfOtpNotIssuedByContactVerification() throws NextStepClientException {
        final String contactValue = "user@test.test";
        final String userId = createUserWithContact(contactValue);

        // A plain OTP crafted to match the contact binding but carrying no persisted verification method
        // must not be confirmable through the contact verification flow.
        final String bindingHash = bindingHash(CONTACT_NAME, CONTACT_TYPE, contactValue);
        final com.wultra.security.powerauth.lib.nextstep.model.response.CreateOtpResponse plainOtp =
                nextStepClient.createOtp(userId, "TEST_OTP", null, bindingHash).getResponseObject();

        // Starting a contact verification triggers cleanup of OTPs bound to this contact. The plain OTP shares the
        // binding hash but is not a contact-verification OTP (no verification method), so cleanup must leave it ACTIVE.
        startOtp(userId);
        assertEquals(OtpStatus.ACTIVE, nextStepClient.getOtpDetail(plainOtp.getOtpId(), null)
                .getResponseObject().getOtpDetail().getOtpStatus());

        final ConfirmContactVerificationResponse confirm =
                confirm(userId, CONTACT_NAME, plainOtp.getOtpId(), plainOtp.getOtpValue(), null);

        assertFalse(confirm.isVerified());
        assertNull(singleContact(userId).getVerificationMethod());
    }

    @Test
    void rejectsStartWithManualMethod() throws NextStepClientException {
        final String userId = createUserWithContact("user@test.test");

        final NextStepClientException thrown = assertThrows(NextStepClientException.class,
                () -> nextStepClient.startContactVerification(userId, CONTACT_NAME, CONTACT_TYPE,
                        ContactVerificationMethod.MANUAL, OTP_DEFINITION));
        assertEquals(InvalidRequestException.CODE, thrown.getError().getCode());
    }

    @Test
    void rejectsConfirmationForUnknownUserOrContactGenerically() throws NextStepClientException {
        final String userId = createUserWithContact("user@test.test");
        final StartContactVerificationResponse start = startOtp(userId);

        // An unknown contact name and an unknown user must both fail generically (verified=false, 200), exactly like a
        // wrong OTP, rather than throwing (which would leak whether the user/contact exists).
        final ConfirmContactVerificationResponse unknownContact =
                confirm(userId, "NO_SUCH_CONTACT", start.getVerificationId(), start.getOtpValue(), null);
        assertFalse(unknownContact.isVerified());
        assertNull(unknownContact.getRemainingAttempts());

        final ConfirmContactVerificationResponse unknownUser =
                confirm(UUID.randomUUID().toString(), CONTACT_NAME, start.getVerificationId(), start.getOtpValue(), null);
        assertFalse(unknownUser.isVerified());
        assertNull(unknownUser.getRemainingAttempts());
    }

    @Test
    void rejectsDeeplinkStartWithMessageTemplateMissingTokenPlaceholder() throws NextStepClientException {
        final String userId = createUserWithContact("user@test.test");

        final NextStepClientException thrown = assertThrows(NextStepClientException.class,
                () -> startDeeplink(userId, "https://example.com/verify", "https://example.com/verify?code=static"));
        assertEquals(InvalidRequestException.CODE, thrown.getError().getCode());
    }

    @Test
    void substitutesTokenPlaceholderInDeeplinkMessageTemplate() throws NextStepClientException {
        final String userId = createUserWithContact("user@test.test");

        final StartContactVerificationResponse start =
                startDeeplink(userId, "https://example.com/verify", "https://example.com/verify?token={token}");
        assertNotNull(start.getDeeplinkUrl());
        assertTrue(start.getDeeplinkUrl().contains("token="));
        assertFalse(start.getDeeplinkUrl().contains("{token}"));
    }

    @Test
    void rejectsStartWhenOtpDefinitionUsesDeterministicAlgorithm() throws NextStepClientException {
        final String userId = createUserWithContact("user@test.test");

        // TEST_OTP uses the OTP_DATA_DIGEST (deterministic) algorithm, which would make the OTP value predictable.
        final NextStepClientException thrown = assertThrows(NextStepClientException.class,
                () -> nextStepClient.startContactVerification(userId, CONTACT_NAME, CONTACT_TYPE,
                        ContactVerificationMethod.OTP, DIGEST_OTP_DEFINITION));
        assertEquals(InvalidConfigurationException.CODE, thrown.getError().getCode());
    }

    @Test
    void rejectsStartWhenOtpDefinitionHasNoAttemptLimit() throws NextStepClientException {
        final String userId = createUserWithContact("user@test.test");

        final NextStepClientException thrown = assertThrows(NextStepClientException.class,
                () -> nextStepClient.startContactVerification(userId, CONTACT_NAME, CONTACT_TYPE,
                        ContactVerificationMethod.OTP, NO_LIMIT_OTP_DEFINITION));
        assertEquals(InvalidConfigurationException.CODE, thrown.getError().getCode());
    }

    @Test
    void rejectsConfirmationWhenAttemptLimitWeakenedAfterStart() throws NextStepClientException {
        final String userId = createUserWithContact("user@test.test");

        // Scenario 1: removing the limit (null) after start must not enable unbounded guessing.
        final StartContactVerificationResponse removed = nextStepClient.startContactVerification(userId, CONTACT_NAME,
                CONTACT_TYPE, ContactVerificationMethod.OTP, MUTABLE_OTP_DEFINITION).getResponseObject();
        setMutablePolicyLimit(null);
        final ConfirmContactVerificationResponse afterRemoval =
                confirm(userId, CONTACT_NAME, removed.getVerificationId(), removed.getOtpValue(), null);
        assertFalse(afterRemoval.isVerified());
        assertNull(afterRemoval.getRemainingAttempts());
        // The OTP is invalidated, so even the correct value cannot be retried.
        assertEquals(OtpStatus.REMOVED, nextStepClient.getOtpDetail(removed.getVerificationId(), null)
                .getResponseObject().getOtpDetail().getOtpStatus());

        // Scenario 2: lowering the limit below the already-recorded failed attempts must also invalidate the OTP,
        // because authentication only blocks when the remaining attempts reach exactly zero, never when negative.
        setMutablePolicyLimit(3);
        final StartContactVerificationResponse lowered = nextStepClient.startContactVerification(userId, CONTACT_NAME,
                CONTACT_TYPE, ContactVerificationMethod.OTP, MUTABLE_OTP_DEFINITION).getResponseObject();
        confirm(userId, CONTACT_NAME, lowered.getVerificationId(), "00000000", null);
        confirm(userId, CONTACT_NAME, lowered.getVerificationId(), "00000000", null);
        setMutablePolicyLimit(1);
        final ConfirmContactVerificationResponse afterLowering =
                confirm(userId, CONTACT_NAME, lowered.getVerificationId(), lowered.getOtpValue(), null);
        assertFalse(afterLowering.isVerified());
        assertNull(afterLowering.getRemainingAttempts());
        assertEquals(OtpStatus.REMOVED, nextStepClient.getOtpDetail(lowered.getVerificationId(), null)
                .getResponseObject().getOtpDetail().getOtpStatus());

        // Restore a finite limit so the shared definition stays usable for any later run.
        setMutablePolicyLimit(3);
    }

    private void setMutablePolicyLimit(final Integer attemptLimit) throws NextStepClientException {
        final UpdateOtpPolicyRequest update = new UpdateOtpPolicyRequest();
        update.setOtpPolicyName(MUTABLE_OTP_POLICY);
        update.setLength(8);
        update.setAttemptLimit(attemptLimit);
        update.setExpirationTime(300L);
        update.setGenAlgorithm(OtpGenerationAlgorithm.OTP_RANDOM_DIGIT_GROUPS);
        final OtpGenerationParam genParam = new OtpGenerationParam();
        genParam.setGroupSize(2);
        update.setGenParam(genParam);
        nextStepClient.updateOtpPolicy(update);
    }

    @Test
    void rejectsDeeplinkHostNotOnAllowList() throws NextStepClientException {
        final String userId = createUserWithContact("user@test.test");
        contactVerificationConfiguration.setAllowedUrlHosts(List.of("allowed.example.com"));

        final NextStepClientException thrown = assertThrows(NextStepClientException.class,
                () -> startDeeplink(userId, "https://evil.example.com/verify"));
        assertEquals(InvalidRequestException.CODE, thrown.getError().getCode());

        // A host on the allow-list still succeeds.
        final StartContactVerificationResponse start = startDeeplink(userId, "https://allowed.example.com/verify");
        assertNotNull(start.getDeeplinkUrl());
    }

    @Test
    void rejectsDeeplinkSchemeNotOnAllowList() throws NextStepClientException {
        final String userId = createUserWithContact("user@test.test");
        contactVerificationConfiguration.setAllowedUrlSchemes(List.of("https"));

        final NextStepClientException thrown = assertThrows(NextStepClientException.class,
                () -> startDeeplink(userId, "myapp://verify"));
        assertEquals(InvalidRequestException.CODE, thrown.getError().getCode());

        // A scheme on the allow-list still succeeds.
        final StartContactVerificationResponse start = startDeeplink(userId, "https://example.com/verify");
        assertNotNull(start.getDeeplinkUrl());
    }

    @Test
    void rejectsOtpConfirmationAfterExpiry() throws Exception {
        final String userId = createUserWithContact("user@test.test");
        final StartContactVerificationResponse start = nextStepClient.startContactVerification(userId, CONTACT_NAME, CONTACT_TYPE,
                ContactVerificationMethod.OTP, EXPIRING_OTP_DEFINITION).getResponseObject();

        // Wait until the OTP (1s expiry) is past its expiration, then confirm with the correct value -> still fails.
        Thread.sleep(1500L);
        final ConfirmContactVerificationResponse confirm =
                confirm(userId, CONTACT_NAME, start.getVerificationId(), start.getOtpValue(), null);

        assertFalse(confirm.isVerified());
        assertNull(singleContact(userId).getVerificationMethod());
    }

    @Test
    void rejectsStartWhenOtpDefinitionHasNoExpiration() throws NextStepClientException {
        final String userId = createUserWithContact("user@test.test");

        final NextStepClientException thrown = assertThrows(NextStepClientException.class,
                () -> nextStepClient.startContactVerification(userId, CONTACT_NAME, CONTACT_TYPE,
                        ContactVerificationMethod.OTP, NO_EXPIRY_OTP_DEFINITION));
        assertEquals(InvalidConfigurationException.CODE, thrown.getError().getCode());
    }

    @Test
    void insertsTokenBeforeUrlFragmentInDeeplinkFallback() throws NextStepClientException {
        final String userId = createUserWithContact("user@test.test");

        final StartContactVerificationResponse start = startDeeplink(userId, "https://example.com/verify#section");
        // The token must be a query parameter placed before the preserved fragment, not inside it.
        assertTrue(start.getDeeplinkUrl().matches("https://example\\.com/verify\\?token=[^#]+#section"));
    }

    @Test
    void rollsBackStartWhenFinalDeeplinkUrlInvalid() throws NextStepClientException {
        final String userId = createUserWithContact("user@test.test");
        final StartContactVerificationResponse first = startOtp(userId);

        // A template with {token} passes the placeholder check but builds a dangerous final URL that fails validation
        // after the earlier OTP was removed and a replacement created; the whole start must roll back.
        assertThrows(NextStepClientException.class,
                () -> startDeeplink(userId, "https://example.com/verify", "javascript:{token}"));

        // Because the failed start rolled back, the original verification is untouched and still confirms.
        assertTrue(confirm(userId, CONTACT_NAME, first.getVerificationId(), first.getOtpValue(), null).isVerified());
    }

    @Test
    void rejectsContactUpdateForRemovedUser() throws NextStepClientException {
        final String userId = createUserWithContact("user@test.test");
        nextStepClient.deleteUser(userId);

        final NextStepClientException thrown = assertThrows(NextStepClientException.class,
                () -> nextStepClient.updateUserContact(userId, CONTACT_NAME, CONTACT_TYPE, "changed@test.test", false));
        assertEquals(UserNotFoundException.CODE, thrown.getError().getCode());
    }

    @Test
    void doesNotReuseOldPendingOtpAfterContactDeleteAndRecreate() throws NextStepClientException {
        final String userId = createUserWithContact("user@test.test");
        final StartContactVerificationResponse start = startOtp(userId);

        nextStepClient.deleteUserContact(userId, CONTACT_NAME, CONTACT_TYPE);
        nextStepClient.createUserContact(userId, CONTACT_NAME, CONTACT_TYPE, "user@test.test", true);

        // The old pending OTP was invalidated on delete and must not confirm the recreated contact.
        assertFalse(confirm(userId, CONTACT_NAME, start.getVerificationId(), start.getOtpValue(), null).isVerified());
    }

    @Test
    void resetsVerificationAndInvalidatesPendingOtpOnContactValueChangeViaUserUpdate() throws NextStepClientException {
        final String userId = createUserWithContact("user@test.test");
        final StartContactVerificationResponse verified = startOtp(userId);
        assertTrue(confirm(userId, CONTACT_NAME, verified.getVerificationId(), verified.getOtpValue(), null).isVerified());
        // Start a second OTP but leave it pending.
        final StartContactVerificationResponse pending = startOtp(userId);

        final UpdateUserRequest request = new UpdateUserRequest();
        request.setUserId(userId);
        final UpdateUserRequest.UpdatedContact contact = new UpdateUserRequest.UpdatedContact();
        contact.setContactName(CONTACT_NAME);
        contact.setContactType(CONTACT_TYPE);
        contact.setContactValue("changed@test.test");
        contact.setPrimary(true);
        request.setContacts(List.of(contact));
        final UpdateUserResponse response = nextStepClient.updateUser(request).getResponseObject();

        final UserContactDetail updated = response.getContacts().stream()
                .filter(c -> CONTACT_NAME.equals(c.getContactName()))
                .findFirst().orElseThrow();
        assertNull(updated.getVerificationMethod());
        assertNull(updated.getTimestampVerified());
        // The pending OTP bound to the old value was invalidated by the value change.
        assertFalse(confirm(userId, CONTACT_NAME, pending.getVerificationId(), pending.getOtpValue(), null).isVerified());
    }

    @Test
    void rejectsContactVerificationOtpAtGenericEndpoint() throws NextStepClientException {
        final String userId = createUserWithContact("user@test.test");
        final StartContactVerificationResponse start = startOtp(userId);

        final NextStepClientException thrown = assertThrows(NextStepClientException.class,
                () -> nextStepClient.authenticateWithOtp(start.getVerificationId(), start.getOtpValue()));
        assertEquals(InvalidRequestException.CODE, thrown.getError().getCode());
    }

    @Test
    void concurrentConfirmsWithCorrectOtpVerifyExactlyOnce() throws Exception {
        final String userId = createUserWithContact("user@test.test");
        final StartContactVerificationResponse start = startOtp(userId);

        // Two correct confirmations racing on the same OTP: the per-user lock must serialize them so the OTP is
        // consumed exactly once - otherwise both could observe the ACTIVE OTP and both succeed.
        final List<ConfirmContactVerificationResponse> results = runConcurrently(2,
                () -> confirm(userId, CONTACT_NAME, start.getVerificationId(), start.getOtpValue(), null));

        final long verified = results.stream().filter(r -> r != null && r.isVerified()).count();
        assertEquals(1, verified);
        assertEquals(ContactVerificationMethod.OTP, singleContact(userId).getVerificationMethod());
    }

    @Test
    void concurrentWrongConfirmsNeverExceedAttemptLimit() throws Exception {
        final String userId = createUserWithContact("user@test.test");
        final StartContactVerificationResponse start = startOtp(userId);

        // Five wrong confirmations race under attempt limit 3. With the per-user lock the failed attempts cannot be
        // lost, so the limit is reached and the OTP is invalidated; the correct value must then no longer verify.
        runConcurrently(5, () -> confirm(userId, CONTACT_NAME, start.getVerificationId(), "00000000", null));

        assertFalse(confirm(userId, CONTACT_NAME, start.getVerificationId(), start.getOtpValue(), null).isVerified());
        assertNull(singleContact(userId).getVerificationMethod());
    }

    @Test
    void concurrentStartsLeaveExactlyOneActiveOtp() throws Exception {
        final String userId = createUserWithContact("user@test.test");

        // Two starts race. The per-user lock must serialize the remove-then-create sequence so only one OTP remains
        // ACTIVE; without it both could create an OTP, leaving two independently confirmable credentials.
        final List<StartContactVerificationResponse> starts = runConcurrently(2, () -> startOtp(userId));

        long active = 0;
        for (StartContactVerificationResponse s : starts) {
            if (s != null && nextStepClient.getOtpDetail(s.getVerificationId(), null)
                    .getResponseObject().getOtpDetail().getOtpStatus() == OtpStatus.ACTIVE) {
                active++;
            }
        }
        assertEquals(1, active);
    }

    @Test
    void concurrentContactValueChangeVsConfirmNeverVerifiesStaleValue() throws Exception {
        final String userId = createUserWithContact("user@test.test");
        final StartContactVerificationResponse start = startOtp(userId);

        // A value change and a confirmation of the OTP bound to the old value race. The per-user lock serializes them,
        // and in either order the contact must not end up verified against the old value: if the change wins, the
        // confirmation sees a binding mismatch; if the confirmation wins, the subsequent change resets the verification.
        final List<Callable<Object>> tasks = List.of(
                () -> nextStepClient.updateUserContact(userId, CONTACT_NAME, CONTACT_TYPE, "changed@test.test", true),
                () -> confirm(userId, CONTACT_NAME, start.getVerificationId(), start.getOtpValue(), null));
        runConcurrently(tasks);

        final UserContactDetail contact = singleContact(userId);
        assertEquals("changed@test.test", contact.getContactValue());
        assertNull(contact.getVerificationMethod());
    }

    private <T> List<T> runConcurrently(final int threads, final Callable<T> task) throws InterruptedException {
        final List<Callable<T>> tasks = new ArrayList<>();
        for (int i = 0; i < threads; i++) {
            tasks.add(task);
        }
        return runConcurrently(tasks);
    }

    private <T> List<T> runConcurrently(final List<Callable<T>> tasks) throws InterruptedException {
        final CyclicBarrier barrier = new CyclicBarrier(tasks.size());
        final ExecutorService pool = Executors.newFixedThreadPool(tasks.size());
        try {
            final List<Callable<T>> wrapped = new ArrayList<>();
            for (final Callable<T> task : tasks) {
                // Release all threads from the barrier together so the calls actually overlap, without any sleeps.
                wrapped.add(() -> {
                    barrier.await();
                    return task.call();
                });
            }
            final List<T> results = new ArrayList<>();
            for (final Future<T> future : pool.invokeAll(wrapped)) {
                try {
                    results.add(future.get());
                } catch (ExecutionException ex) {
                    results.add(null);
                }
            }
            return results;
        } finally {
            pool.shutdownNow();
        }
    }

    private StartContactVerificationResponse startOtp(final String userId) throws NextStepClientException {
        return nextStepClient.startContactVerification(userId, CONTACT_NAME, CONTACT_TYPE,
                ContactVerificationMethod.OTP, OTP_DEFINITION).getResponseObject();
    }

    private StartContactVerificationResponse startDeeplink(final String userId, final String baseUrl) throws NextStepClientException {
        return startDeeplink(userId, baseUrl, null);
    }

    private StartContactVerificationResponse startDeeplink(final String userId, final String baseUrl, final String messageTemplate) throws NextStepClientException {
        final com.wultra.security.powerauth.lib.nextstep.model.request.StartContactVerificationRequest request =
                new com.wultra.security.powerauth.lib.nextstep.model.request.StartContactVerificationRequest();
        request.setUserId(userId);
        request.setContactName(CONTACT_NAME);
        request.setContactType(CONTACT_TYPE);
        request.setMethod(ContactVerificationMethod.DEEPLINK);
        request.setOtpDefinitionName(OTP_DEFINITION);
        request.setDeeplinkBaseUrl(baseUrl);
        request.setMessageTemplate(messageTemplate);
        return nextStepClient.startContactVerification(request).getResponseObject();
    }

    private ConfirmContactVerificationResponse confirm(final String userId, final String contactName,
                                                       final String verificationId, final String otpValue, final String token) throws NextStepClientException {
        return nextStepClient.confirmContactVerification(userId, contactName, CONTACT_TYPE, verificationId, otpValue, token).getResponseObject();
    }

    private String createUserWithContact(final String value) throws NextStepClientException {
        final String userId = UUID.randomUUID().toString();
        nextStepClient.createUser(newUserRequest(userId));
        nextStepClient.createUserContact(userId, CONTACT_NAME, CONTACT_TYPE, value, true);
        return userId;
    }

    private CreateUserRequest newUserRequest(final String userId) {
        final CreateUserRequest request = new CreateUserRequest();
        request.setUserId(userId);
        return request;
    }

    private UserContactDetail singleContact(final String userId) throws NextStepClientException {
        return singleContact(userId, CONTACT_NAME);
    }

    private UserContactDetail singleContact(final String userId, final String contactName) throws NextStepClientException {
        return nextStepClient.getUserContactList(userId).getResponseObject().getContacts().stream()
                .filter(c -> contactName.equals(c.getContactName()))
                .findFirst()
                .orElseThrow();
    }

    private String extractToken(final String url) {
        final int index = url.indexOf("token=");
        assertTrue(index >= 0);
        final String raw = url.substring(index + "token=".length());
        return java.net.URLDecoder.decode(raw, java.nio.charset.StandardCharsets.UTF_8);
    }

    private String bindingHash(final String contactName, final ContactType contactType, final String contactValue) {
        final byte[] nameBytes = contactName.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        final String typeName = contactType.name();
        final byte[] typeBytes = typeName.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        final byte[] valueBytes = contactValue.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        final String input = nameBytes.length + ":" + contactName + ":" + typeBytes.length + ":" + typeName + ":" + valueBytes.length + ":" + contactValue;
        final byte[] hash;
        try {
            hash = java.security.MessageDigest.getInstance("SHA-256")
                    .digest(input.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        } catch (java.security.NoSuchAlgorithmException ex) {
            throw new IllegalStateException(ex);
        }
        final StringBuilder hex = new StringBuilder(hash.length * 2);
        for (byte b : hash) {
            hex.append(Character.forDigit((b >> 4) & 0xF, 16));
            hex.append(Character.forDigit(b & 0xF, 16));
        }
        return hex.toString();
    }

    private void ensureVerificationOtpDefinition() throws NextStepClientException {
        final OtpGenerationParam genParam = new OtpGenerationParam();
        genParam.setGroupSize(2);
        // Standard definition used by the happy-path and most negative tests.
        provisionOtp("CONTACT_VERIFICATION_OTP_POLICY", OTP_DEFINITION, 3, 300L, genParam);
        // Definitions that each violate one start-time configuration guard.
        provisionOtp("CONTACT_VERIFICATION_NO_LIMIT_POLICY", NO_LIMIT_OTP_DEFINITION, null, 300L, genParam);
        provisionOtp("CONTACT_VERIFICATION_NO_EXPIRY_POLICY", NO_EXPIRY_OTP_DEFINITION, 3, null, genParam);
        // Short-lived definition used to assert that an expired OTP cannot be confirmed.
        provisionOtp("CONTACT_VERIFICATION_EXPIRING_POLICY", EXPIRING_OTP_DEFINITION, 3, 1L, genParam);
        // Dedicated definition whose policy is mutated by a single test; kept separate so the mutation cannot affect others.
        provisionOtp(MUTABLE_OTP_POLICY, MUTABLE_OTP_DEFINITION, 3, 300L, genParam);
    }

    private void provisionOtp(final String policyName, final String definitionName, final Integer attemptLimit,
                              final Long expirationTime, final OtpGenerationParam genParam) {
        final CreateOtpPolicyRequest policy = new CreateOtpPolicyRequest();
        policy.setOtpPolicyName(policyName);
        policy.setAttemptLimit(attemptLimit);
        policy.setLength(8);
        policy.setExpirationTime(expirationTime);
        policy.setGenAlgorithm(OtpGenerationAlgorithm.OTP_RANDOM_DIGIT_GROUPS);
        policy.setGenParam(genParam);
        final CreateOtpDefinitionRequest definition = new CreateOtpDefinitionRequest();
        definition.setOtpDefinitionName(definitionName);
        definition.setApplicationName("TEST_APP");
        definition.setOtpPolicyName(policyName);
        try {
            nextStepClient.createOtpPolicy(policy);
            nextStepClient.createOtpDefinition(definition);
        } catch (NextStepClientException ex) {
            // Policy/definition already provisioned by an earlier test in the shared Spring context.
        }
    }

}
