-- Changeset powerauth-nextstep/2.3.x/20261026-add-contact-verification.xml::1::Roman Strobl
-- Add column verification_method to ns_user_contact
ALTER TABLE ns_user_contact ADD verification_method VARCHAR2(32 CHAR);

-- Changeset powerauth-nextstep/2.3.x/20261026-add-contact-verification.xml::2::Roman Strobl
-- Add column timestamp_verified to ns_user_contact
ALTER TABLE ns_user_contact ADD timestamp_verified TIMESTAMP;

-- Changeset powerauth-nextstep/2.3.x/20261026-add-contact-verification.xml::3::Roman Strobl
-- Add column otp_purpose to ns_otp_storage to distinguish regular OTPs from contact verification OTPs
ALTER TABLE ns_otp_storage ADD otp_purpose VARCHAR2(32 CHAR) DEFAULT 'GENERIC' NOT NULL;
