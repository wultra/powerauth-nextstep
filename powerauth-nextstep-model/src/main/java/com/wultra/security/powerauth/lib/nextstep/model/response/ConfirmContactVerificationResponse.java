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

import com.wultra.security.powerauth.lib.nextstep.model.entity.enumeration.ContactVerificationMethod;
import lombok.Data;

import java.util.Date;

/**
 * Response object used for confirming verification of a user contact.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Data
public class ConfirmContactVerificationResponse {

    /**
     * Whether the contact was successfully verified.
     */
    private boolean verified;

    /**
     * Number of remaining verification attempts, or {@code null} if not applicable.
     */
    private Integer remainingAttempts;

    /**
     * Method used to verify the contact, or {@code null} when verification failed.
     */
    private ContactVerificationMethod verificationMethod;

    /**
     * Timestamp when the contact was verified, or {@code null} when verification failed.
     */
    private Date timestampVerified;

}
