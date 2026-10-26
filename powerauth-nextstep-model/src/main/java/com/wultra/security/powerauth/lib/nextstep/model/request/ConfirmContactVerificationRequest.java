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
package com.wultra.security.powerauth.lib.nextstep.model.request;

import com.wultra.security.powerauth.lib.nextstep.model.entity.enumeration.ContactType;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.Data;
import lombok.ToString;

/**
 * Request object used for confirming verification of a user contact.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Data
public class ConfirmContactVerificationRequest {

    /**
     * Identifier of the user whose contact is being verified.
     */
    @NotBlank
    @Size(min = 1, max = 256)
    private String userId;

    /**
     * Name of the contact being verified.
     */
    @NotBlank
    @Size(min = 2, max = 256)
    private String contactName;

    /**
     * Type of the contact being verified.
     */
    @NotNull
    private ContactType contactType;

    /**
     * Opaque verification identifier returned when the verification was started.
     */
    @NotBlank
    @Size(min = 36, max = 36)
    private String verificationId;

    /**
     * OTP value entered by the user for the {@code OTP} method.
     */
    @ToString.Exclude
    private String otpValue;

    /**
     * Token extracted by the caller from the deeplink for the {@code DEEPLINK} method.
     */
    @ToString.Exclude
    private String token;

}
