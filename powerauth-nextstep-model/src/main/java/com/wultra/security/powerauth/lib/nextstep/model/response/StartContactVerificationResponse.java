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
package com.wultra.security.powerauth.lib.nextstep.model.response;

import com.wultra.security.powerauth.lib.nextstep.model.entity.enumeration.ContactType;
import com.wultra.security.powerauth.lib.nextstep.model.entity.enumeration.ContactVerificationMethod;
import lombok.Data;
import lombok.ToString;

import java.util.Date;

/**
 * Response object used for starting verification of a user contact. The caller is responsible for delivering the OTP value
 * or deeplink URL to the contact.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Data
public class StartContactVerificationResponse {

    /**
     * Opaque identifier of the verification, to be supplied when confirming.
     */
    private String verificationId;

    /**
     * Name of the contact being verified.
     */
    private String contactName;

    /**
     * Type of the contact being verified.
     */
    private ContactType contactType;

    /**
     * Value of the contact being verified.
     */
    private String contactValue;

    /**
     * Verification method that was started.
     */
    private ContactVerificationMethod method;

    /**
     * Timestamp when the verification expires.
     */
    private Date expiresAt;

    /**
     * Generated OTP value to be delivered to the contact. Set only for the {@code OTP} method.
     */
    @ToString.Exclude
    private String otpValue;

    /**
     * Deeplink URL to be delivered to the contact. Set only for the {@code DEEPLINK} method.
     */
    @ToString.Exclude
    private String deeplinkUrl;

}
