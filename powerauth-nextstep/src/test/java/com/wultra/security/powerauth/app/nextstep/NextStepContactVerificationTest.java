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
package com.wultra.security.powerauth.app.nextstep;

import com.wultra.security.powerauth.lib.nextstep.client.NextStepClientException;
import com.wultra.security.powerauth.lib.nextstep.model.entity.OtpGenerationParam;
import com.wultra.security.powerauth.lib.nextstep.model.entity.UserContactDetail;
import com.wultra.security.powerauth.lib.nextstep.model.entity.enumeration.ContactType;
import com.wultra.security.powerauth.lib.nextstep.model.entity.enumeration.ContactVerificationMethod;
import com.wultra.security.powerauth.lib.nextstep.model.enumeration.OtpGenerationAlgorithm;
import com.wultra.security.powerauth.lib.nextstep.model.exception.InvalidRequestException;
import com.wultra.security.powerauth.lib.nextstep.model.exception.UserContactNotFoundException;
import com.wultra.security.powerauth.lib.nextstep.model.request.CreateOtpDefinitionRequest;
import com.wultra.security.powerauth.lib.nextstep.model.request.CreateOtpPolicyRequest;
import com.wultra.security.powerauth.lib.nextstep.model.request.CreateUserRequest;
import com.wultra.security.powerauth.lib.nextstep.model.response.ConfirmContactVerificationResponse;
import com.wultra.security.powerauth.lib.nextstep.model.response.StartContactVerificationResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Date;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Next Step contact verification flow tests (OTP and deeplink).
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
class NextStepContactVerificationTest extends NextStepTest {

    private static final String OTP_DEFINITION = "CONTACT_VERIFICATION_OTP";
    private static final String CONTACT_NAME = "TEST_CONTACT";
    private static final ContactType CONTACT_TYPE = ContactType.EMAIL;

    @BeforeEach
    void setUp() throws Exception {
        nextStepClient = nextStepClientFactory.createNextStepClient("http://localhost:" + port);
        nextStepTestConfiguration.configure(nextStepClient);
        ensureVerificationOtpDefinition();
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
        assertNotNull(confirm.getRemainingAttempts());
        assertTrue(confirm.getRemainingAttempts() < 3);
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
    void rejectsOtpConfirmationAfterContactValueChanged() throws NextStepClientException {
        final String userId = createUserWithContact("user@test.test");
        final StartContactVerificationResponse start = startOtp(userId);

        nextStepClient.updateUserContact(userId, CONTACT_NAME, CONTACT_TYPE, "changed@test.test", true);

        final ConfirmContactVerificationResponse confirm =
                confirm(userId, CONTACT_NAME, start.getVerificationId(), start.getOtpValue(), null);

        assertFalse(confirm.isVerified());
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

    private StartContactVerificationResponse startOtp(final String userId) throws NextStepClientException {
        return nextStepClient.startContactVerification(userId, CONTACT_NAME, CONTACT_TYPE,
                ContactVerificationMethod.OTP, OTP_DEFINITION).getResponseObject();
    }

    private StartContactVerificationResponse startDeeplink(final String userId, final String baseUrl) throws NextStepClientException {
        final com.wultra.security.powerauth.lib.nextstep.model.request.StartContactVerificationRequest request =
                new com.wultra.security.powerauth.lib.nextstep.model.request.StartContactVerificationRequest();
        request.setUserId(userId);
        request.setContactName(CONTACT_NAME);
        request.setContactType(CONTACT_TYPE);
        request.setMethod(ContactVerificationMethod.DEEPLINK);
        request.setOtpDefinitionName(OTP_DEFINITION);
        request.setDeeplinkBaseUrl(baseUrl);
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
        return url.substring(index + "token=".length());
    }

    private String bindingHash(final String contactName, final ContactType contactType, final String contactValue) {
        final String input = contactName + '|' + contactType.name() + '|' + contactValue;
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
        final CreateOtpPolicyRequest policyRequest = new CreateOtpPolicyRequest();
        policyRequest.setOtpPolicyName("CONTACT_VERIFICATION_OTP_POLICY");
        policyRequest.setAttemptLimit(3);
        policyRequest.setLength(8);
        policyRequest.setExpirationTime(300L);
        policyRequest.setGenAlgorithm(OtpGenerationAlgorithm.OTP_RANDOM_DIGIT_GROUPS);
        policyRequest.setGenParam(genParam);
        try {
            nextStepClient.createOtpPolicy(policyRequest);
        } catch (NextStepClientException ex) {
            // Policy already provisioned by an earlier test in the shared context.
        }

        final CreateOtpDefinitionRequest definitionRequest = new CreateOtpDefinitionRequest();
        definitionRequest.setOtpDefinitionName(OTP_DEFINITION);
        definitionRequest.setApplicationName("TEST_APP");
        definitionRequest.setOtpPolicyName("CONTACT_VERIFICATION_OTP_POLICY");
        try {
            nextStepClient.createOtpDefinition(definitionRequest);
        } catch (NextStepClientException ex) {
            // Definition already provisioned by an earlier test in the shared context.
        }
    }

}
