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
package com.wultra.security.powerauth.lib.nextstep.model.request;

import com.wultra.security.powerauth.lib.nextstep.model.entity.enumeration.ContactType;
import com.wultra.security.powerauth.lib.nextstep.model.entity.enumeration.ContactVerificationMethod;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.Data;

/**
 * Request object used for starting verification of a user contact.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Data
public class StartContactVerificationRequest {

    /**
     * Identifier of the user whose contact is being verified.
     */
    @NotBlank
    @Size(min = 1, max = 256)
    private String userId;

    /**
     * Name of the contact to verify.
     */
    @NotBlank
    @Size(min = 2, max = 256)
    private String contactName;

    /**
     * Type of the contact to verify.
     */
    @NotNull
    private ContactType contactType;

    /**
     * Verification method to use. Only {@code OTP} or {@code DEEPLINK} may be started.
     */
    @NotNull
    private ContactVerificationMethod method;

    /**
     * Name of the OTP definition used to issue the verification OTP. The referenced definition must use a random generation algorithm.
     */
    @NotBlank
    @Size(min = 2, max = 256)
    private String otpDefinitionName;

    /**
     * Base URL used to build the deeplink for the {@code DEEPLINK} method. Ignored for the {@code OTP} method.
     */
    private String deeplinkBaseUrl;

    /**
     * Optional caller-owned message template containing a {@code {token}} placeholder for the {@code DEEPLINK} method.
     */
    private String messageTemplate;

    /**
     * Optional language of the delivered message (caller responsibility).
     */
    private String language;

}
