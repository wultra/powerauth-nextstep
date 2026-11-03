-- Changeset powerauth-nextstep/2.3.x/20261026-add-contact-verification.xml::1::Roman Strobl
-- Add column verification_method to ns_user_contact
ALTER TABLE ns_user_contact ADD verification_method VARCHAR2(32 CHAR);

-- Changeset powerauth-nextstep/2.3.x/20261026-add-contact-verification.xml::2::Roman Strobl
-- Add column timestamp_verified to ns_user_contact
ALTER TABLE ns_user_contact ADD timestamp_verified TIMESTAMP;

-- Changeset powerauth-nextstep/2.3.x/20261026-add-contact-verification.xml::3::Roman Strobl
-- Add column verification_method to ns_otp_storage to persist the contact verification method started for an OTP
ALTER TABLE ns_otp_storage ADD verification_method VARCHAR2(32 CHAR);
