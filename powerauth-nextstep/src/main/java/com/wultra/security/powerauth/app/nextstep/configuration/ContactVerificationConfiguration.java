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
package com.wultra.security.powerauth.app.nextstep.configuration;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.util.ArrayList;
import java.util.List;

/**
 * Configuration of contact verification, in particular the optional allow-lists applied to caller-supplied deeplink URLs.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Configuration
@ConfigurationProperties(prefix = "powerauth.nextstep.contact-verification")
@Getter
@Setter
public class ContactVerificationConfiguration {

    /**
     * Allow-list of hosts accepted in a deeplink URL for {@code http} and {@code https} schemes. When empty, no host restriction is applied.
     */
    private List<String> allowedUrlHosts = new ArrayList<>();

    /**
     * Allow-list of URL schemes accepted in a deeplink URL. When empty, no scheme restriction is applied beyond the built-in rejection of dangerous schemes.
     */
    private List<String> allowedUrlSchemes = new ArrayList<>();

}
