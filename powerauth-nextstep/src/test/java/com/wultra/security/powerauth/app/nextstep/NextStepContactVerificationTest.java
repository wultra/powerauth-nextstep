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
import com.wultra.security.powerauth.lib.nextstep.model.request.ConfirmContactVerificationRequest;
import com.wultra.security.powerauth.lib.nextstep.model.request.CreateOtpDefinitionRequest;
import com.wultra.security.powerauth.lib.nextstep.model.request.CreateOtpPolicyRequest;
import com.wultra.security.powerauth.lib.nextstep.model.request.CreateUserRequest;
import com.wultra.security.powerauth.lib.nextstep.model.request.StartContactVerificationRequest;
import com.wultra.security.powerauth.lib.nextstep.model.response.ConfirmContactVerificationResponse;
import com.wultra.security.powerauth.lib.nextstep.model.response.StartContactVerificationResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Next Step contact verification flow tests (OTP and deeplink).
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
class NextStepContactVerificationTest extends NextStepTest {

    private static final String OTP_DEFINITION = "CONTACT_VERIFICATION_OTP";
    private static final String DIGEST_OTP_DEFINITION = "TEST_OTP";
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
        final StartContactVerificationResponse start = start(userId, ContactVerificationMethod.OTP, null, OTP_DEFINITION);

        assertNotNull(start.getOtpValue());
        assertNull(start.getDeeplinkUrl());

        final ConfirmContactVerificationResponse confirm = confirm(userId, start.getVerificationId(), start.getOtpValue(), null);

        assertTrue(confirm.isVerified());
        assertEquals(ContactVerificationMethod.OTP, confirm.getVerificationMethod());
        final UserContactDetail contact = singleContact(userId);
        assertEquals(ContactVerificationMethod.OTP, contact.getVerificationMethod());
        assertNotNull(contact.getTimestampVerified());
    }

    @Test
    void confirmsDeeplinkVerification() throws NextStepClientException {
        final String userId = createUserWithContact("user@test.test");
        final StartContactVerificationResponse start = start(userId, ContactVerificationMethod.DEEPLINK, "https://example.com/verify", OTP_DEFINITION);

        assertNull(start.getOtpValue());
        assertTrue(start.getDeeplinkUrl().startsWith("https://example.com/verify?token="));

        final String token = URLDecoder.decode(start.getDeeplinkUrl().substring(start.getDeeplinkUrl().indexOf("token=") + 6), StandardCharsets.UTF_8);
        final ConfirmContactVerificationResponse confirm = confirm(userId, start.getVerificationId(), null, token);

        assertTrue(confirm.isVerified());
        assertEquals(ContactVerificationMethod.DEEPLINK, singleContact(userId).getVerificationMethod());
    }

    @Test
    void rejectsWrongOtpValue() throws NextStepClientException {
        final String userId = createUserWithContact("user@test.test");
        final StartContactVerificationResponse start = start(userId, ContactVerificationMethod.OTP, null, OTP_DEFINITION);

        final ConfirmContactVerificationResponse confirm = confirm(userId, start.getVerificationId(), "00000000", null);

        assertFalse(confirm.isVerified());
        assertNull(singleContact(userId).getVerificationMethod());
    }

    @Test
    void rejectsConfirmationAfterContactValueChange() throws NextStepClientException {
        final String userId = createUserWithContact("user@test.test");
        final StartContactVerificationResponse start = start(userId, ContactVerificationMethod.OTP, null, OTP_DEFINITION);
        nextStepClient.updateUserContact(userId, CONTACT_NAME, CONTACT_TYPE, "changed@test.test", true);
        // Changing the value back must not revive the pending verification
        nextStepClient.updateUserContact(userId, CONTACT_NAME, CONTACT_TYPE, "user@test.test", true);

        final ConfirmContactVerificationResponse confirm = confirm(userId, start.getVerificationId(), start.getOtpValue(), null);

        assertFalse(confirm.isVerified());
        assertNull(singleContact(userId).getVerificationMethod());
    }

    @Test
    void rejectsOtpDefinitionWithDigestAlgorithm() throws NextStepClientException {
        final String userId = createUserWithContact("user@test.test");

        assertThrows(NextStepClientException.class, () -> start(userId, ContactVerificationMethod.OTP, null, DIGEST_OTP_DEFINITION));
    }

    @Test
    void rejectsInvalidStartRequests() throws NextStepClientException {
        final String userId = createUserWithContact("user@test.test");

        assertThrows(NextStepClientException.class, () -> start(userId, ContactVerificationMethod.MANUAL, null, OTP_DEFINITION));
        assertThrows(NextStepClientException.class, () -> start(userId, ContactVerificationMethod.DEEPLINK, null, OTP_DEFINITION));
        assertThrows(NextStepClientException.class, () -> start(userId, ContactVerificationMethod.DEEPLINK, "not-absolute", OTP_DEFINITION));
    }

    private StartContactVerificationResponse start(final String userId, final ContactVerificationMethod method, final String baseUrl,
                                                   final String otpDefinitionName) throws NextStepClientException {
        final StartContactVerificationRequest request = new StartContactVerificationRequest();
        request.setUserId(userId);
        request.setContactName(CONTACT_NAME);
        request.setContactType(CONTACT_TYPE);
        request.setMethod(method);
        request.setOtpDefinitionName(otpDefinitionName);
        request.setDeeplinkBaseUrl(baseUrl);
        return nextStepClient.startContactVerification(request).getResponseObject();
    }

    private ConfirmContactVerificationResponse confirm(final String userId, final String verificationId,
                                                       final String otpValue, final String token) throws NextStepClientException {
        final ConfirmContactVerificationRequest request = new ConfirmContactVerificationRequest();
        request.setUserId(userId);
        request.setContactName(CONTACT_NAME);
        request.setContactType(CONTACT_TYPE);
        request.setVerificationId(verificationId);
        request.setOtpValue(otpValue);
        request.setToken(token);
        return nextStepClient.confirmContactVerification(request).getResponseObject();
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

    private void provisionOtpDefinition() {
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
        try {
            nextStepClient.createOtpPolicy(policy);
            nextStepClient.createOtpDefinition(definition);
        } catch (NextStepClientException ex) {
            // Already provisioned by an earlier test in the shared Spring context.
        }
    }

}
