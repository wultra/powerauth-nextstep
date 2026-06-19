--
-- Create sequences.
--
CREATE SEQUENCE ns_operation_afs_seq MINVALUE 1 INCREMENT BY 1 START WITH 1 CACHE 20;
CREATE SEQUENCE ns_application_seq MINVALUE 1 INCREMENT BY 1 START WITH 1 CACHE 20;
CREATE SEQUENCE ns_credential_policy_seq MINVALUE 1 INCREMENT BY 1 START WITH 1 CACHE 20;
CREATE SEQUENCE ns_otp_policy_seq MINVALUE 1 INCREMENT BY 1 START WITH 1 CACHE 20;
CREATE SEQUENCE ns_user_contact_seq MINVALUE 1 INCREMENT BY 1 START WITH 1 CACHE 20;
CREATE SEQUENCE ns_user_identity_history_seq MINVALUE 1 INCREMENT BY 1 START WITH 1 CACHE 20;
CREATE SEQUENCE ns_role_seq MINVALUE 1 INCREMENT BY 1 START WITH 1 CACHE 20;
CREATE SEQUENCE ns_user_role_seq MINVALUE 1 INCREMENT BY 1 START WITH 1 CACHE 20;
CREATE SEQUENCE ns_user_alias_seq MINVALUE 1 INCREMENT BY 1 START WITH 1 CACHE 20;
CREATE SEQUENCE ns_hashing_config_seq MINVALUE 1 INCREMENT BY 1 START WITH 1 CACHE 20;
CREATE SEQUENCE ns_credential_definition_seq MINVALUE 1 INCREMENT BY 1 START WITH 1 CACHE 20;
CREATE SEQUENCE ns_otp_definition_seq MINVALUE 1 INCREMENT BY 1 START WITH 1 CACHE 20;
CREATE SEQUENCE ns_credential_history_seq MINVALUE 1 INCREMENT BY 1 START WITH 1 CACHE 20;

CREATE TABLE ns_auth_method (
  auth_method VARCHAR(32) PRIMARY KEY NOT NULL,
  order_number INTEGER NOT NULL,
  check_user_prefs BOOLEAN DEFAULT FALSE NOT NULL,
  user_prefs_column INTEGER,
  user_prefs_default BOOLEAN DEFAULT FALSE,
  check_auth_fails BOOLEAN DEFAULT FALSE NOT NULL,
  max_auth_fails INTEGER,
  has_user_interface BOOLEAN DEFAULT FALSE,
  has_mobile_token BOOLEAN DEFAULT FALSE,
  display_name_key VARCHAR(32)
);

CREATE TABLE ns_operation_config (
  operation_name VARCHAR(32) PRIMARY KEY NOT NULL,
  template_version VARCHAR(1) NOT NULL,
  template_id INTEGER NOT NULL,
  mobile_token_enabled BOOLEAN DEFAULT FALSE NOT NULL,
  mobile_token_mode VARCHAR(256) NOT NULL,
  afs_enabled BOOLEAN DEFAULT FALSE NOT NULL,
  afs_config_id VARCHAR(256),
  expiration_time INTEGER
);

CREATE TABLE ns_operation_method_config (
  operation_name VARCHAR(32) NOT NULL,
  auth_method VARCHAR(32) NOT NULL,
  max_auth_fails INTEGER NOT NULL,
  CONSTRAINT ns_operation_method_pk PRIMARY KEY (operation_name, auth_method),
  CONSTRAINT ns_operation_method_fk1 FOREIGN KEY (operation_name) REFERENCES ns_operation_config (operation_name),
  CONSTRAINT ns_operation_method_fk2 FOREIGN KEY (auth_method) REFERENCES ns_auth_method (auth_method)
);

CREATE TABLE ns_organization (
  organization_id VARCHAR(256) PRIMARY KEY NOT NULL,
  display_name_key VARCHAR(256),
  is_default BOOLEAN DEFAULT FALSE NOT NULL,
  order_number INTEGER NOT NULL,
  default_credential_name VARCHAR(256),
  default_otp_name VARCHAR(256)
);

CREATE TABLE ns_step_definition (
  step_definition_id INTEGER PRIMARY KEY NOT NULL,
  operation_name VARCHAR(32) NOT NULL,
  operation_type VARCHAR(32) NOT NULL,
  request_auth_method VARCHAR(32),
  request_auth_step_result VARCHAR(32),
  response_priority INTEGER NOT NULL,
  response_auth_method VARCHAR(32),
  response_result VARCHAR(32) NOT NULL,
  CONSTRAINT step_request_auth_method_fk FOREIGN KEY (request_auth_method) REFERENCES ns_auth_method (auth_method),
  CONSTRAINT step_response_auth_method_fk FOREIGN KEY (response_auth_method) REFERENCES ns_auth_method (auth_method)
);

CREATE TABLE ns_application (
  application_id INTEGER PRIMARY KEY NOT NULL,
  name VARCHAR(256) NOT NULL,
  description VARCHAR(256),
  status VARCHAR(32) NOT NULL,
  timestamp_created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  timestamp_last_updated TIMESTAMP
);

CREATE TABLE ns_credential_policy (
  credential_policy_id INTEGER NOT NULL PRIMARY KEY,
  name VARCHAR(256) NOT NULL,
  description VARCHAR(256) NOT NULL,
  status VARCHAR(32) NOT NULL,
  username_length_min INTEGER,
  username_length_max INTEGER,
  username_allowed_pattern VARCHAR(256),
  credential_length_min INTEGER,
  credential_length_max INTEGER,
  limit_soft INTEGER,
  limit_hard INTEGER,
  check_history_count INTEGER DEFAULT 0 NOT NULL,
  rotation_enabled BOOLEAN DEFAULT FALSE NOT NULL,
  rotation_days INTEGER,
  credential_temp_expiration INTEGER,
  username_gen_algorithm VARCHAR(256) DEFAULT 'DEFAULT' NOT NULL,
  username_gen_param VARCHAR(4000) NOT NULL,
  credential_gen_algorithm VARCHAR(256) DEFAULT 'DEFAULT' NOT NULL,
  credential_gen_param VARCHAR(4000) NOT NULL,
  credential_val_param VARCHAR(4000) NOT NULL,
  timestamp_created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  timestamp_last_updated TIMESTAMP
);

CREATE TABLE ns_otp_policy (
  otp_policy_id INTEGER NOT NULL PRIMARY KEY,
  name VARCHAR(256) NOT NULL,
  description VARCHAR(256),
  status VARCHAR(32) NOT NULL,
  length INTEGER NOT NULL,
  attempt_limit INTEGER,
  expiration_time INTEGER,
  gen_algorithm VARCHAR(256) DEFAULT 'DEFAULT' NOT NULL,
  gen_param VARCHAR(4000) NOT NULL,
  timestamp_created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  timestamp_last_updated TIMESTAMP
);

CREATE TABLE ns_user_identity (
  user_id VARCHAR(256) NOT NULL PRIMARY KEY,
  status VARCHAR(32) NOT NULL,
  extras TEXT,
  timestamp_created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  timestamp_last_updated TIMESTAMP
);

CREATE TABLE ns_user_contact (
  user_contact_id INTEGER NOT NULL PRIMARY KEY,
  user_id VARCHAR(256) NOT NULL,
  name VARCHAR(256) NOT NULL,
  type VARCHAR(32) NOT NULL,
  value VARCHAR(256) NOT NULL,
  is_primary BOOLEAN DEFAULT FALSE NOT NULL,
  timestamp_created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  timestamp_last_updated TIMESTAMP,
  CONSTRAINT ns_user_contact_fk FOREIGN KEY (user_id) REFERENCES ns_user_identity (user_id)
);

CREATE TABLE ns_user_identity_history (
  user_identity_history_id INTEGER NOT NULL PRIMARY KEY,
  user_id VARCHAR(256) NOT NULL,
  status VARCHAR(32) NOT NULL,
  roles VARCHAR(256),
  extras TEXT,
  timestamp_created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT ns_user_identity_history_fk FOREIGN KEY (user_id) REFERENCES ns_user_identity (user_id)
);

CREATE TABLE ns_role (
  role_id INTEGER NOT NULL PRIMARY KEY,
  name VARCHAR(256) NOT NULL,
  description VARCHAR(256),
  timestamp_created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  timestamp_last_updated TIMESTAMP
);

CREATE TABLE ns_user_role (
  user_role_id INTEGER NOT NULL PRIMARY KEY,
  user_id VARCHAR(256) NOT NULL,
  role_id INTEGER NOT NULL,
  status VARCHAR(32) NOT NULL,
  timestamp_created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  timestamp_last_updated TIMESTAMP,
  CONSTRAINT ns_role_identity_fk FOREIGN KEY (user_id) REFERENCES ns_user_identity (user_id),
  CONSTRAINT ns_user_role_fk FOREIGN KEY (role_id) REFERENCES ns_role (role_id)
);

CREATE TABLE ns_user_alias (
  user_alias_id INTEGER NOT NULL PRIMARY KEY,
  user_id VARCHAR(256) NOT NULL,
  name VARCHAR(256) NOT NULL,
  value VARCHAR(256) NOT NULL,
  status VARCHAR(32) NOT NULL,
  extras TEXT,
  timestamp_created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  timestamp_last_updated TIMESTAMP,
  CONSTRAINT ns_user_alias_fk FOREIGN KEY (user_id) REFERENCES ns_user_identity (user_id)
);

CREATE TABLE ns_hashing_config (
  hashing_config_id INTEGER NOT NULL PRIMARY KEY,
  name VARCHAR(256) NOT NULL,
  algorithm VARCHAR(256) NOT NULL,
  status VARCHAR(32) NOT NULL,
  parameters VARCHAR(256),
  timestamp_created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  timestamp_last_updated TIMESTAMP
);

CREATE TABLE ns_credential_definition (
  credential_definition_id INTEGER NOT NULL PRIMARY KEY,
  name VARCHAR(256) NOT NULL,
  description VARCHAR(256),
  application_id INTEGER NOT NULL,
  organization_id VARCHAR(256),
  credential_policy_id INTEGER NOT NULL,
  category VARCHAR(32) NOT NULL,
  encryption_enabled BOOLEAN DEFAULT FALSE NOT NULL,
  encryption_algorithm VARCHAR(256) NOT NULL,
  hashing_enabled BOOLEAN DEFAULT FALSE NOT NULL,
  hashing_config_id INTEGER,
  e2e_encryption_enabled BOOLEAN DEFAULT FALSE NOT NULL,
  e2e_encryption_algorithm VARCHAR(256),
  e2e_encryption_transform VARCHAR(256),
  e2e_encryption_temporary BOOLEAN DEFAULT FALSE NOT NULL,
  data_adapter_proxy_enabled BOOLEAN DEFAULT FALSE NOT NULL,
  status VARCHAR(32) NOT NULL,
  parameters VARCHAR(256),
  timestamp_created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  timestamp_last_updated TIMESTAMP,
  CONSTRAINT ns_credential_application_fk FOREIGN KEY (application_id) REFERENCES ns_application (application_id),
  CONSTRAINT ns_application_organization_fk FOREIGN KEY (organization_id) REFERENCES ns_organization (organization_id),
  CONSTRAINT ns_credential_policy_fk FOREIGN KEY (credential_policy_id) REFERENCES ns_credential_policy (credential_policy_id),
  CONSTRAINT ns_credential_hash_fk FOREIGN KEY (hashing_config_id) REFERENCES ns_hashing_config (hashing_config_id)
);

CREATE TABLE ns_otp_definition (
  otp_definition_id INTEGER NOT NULL PRIMARY KEY,
  name VARCHAR(256) NOT NULL,
  description VARCHAR(256),
  application_id INTEGER NOT NULL,
  otp_policy_id INTEGER NOT NULL,
  encryption_enabled BOOLEAN DEFAULT FALSE NOT NULL,
  encryption_algorithm VARCHAR(256),
  data_adapter_proxy_enabled BOOLEAN DEFAULT FALSE NOT NULL,
  status VARCHAR(32) NOT NULL,
  timestamp_created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  timestamp_last_updated TIMESTAMP,
  CONSTRAINT ns_otp_application_fk FOREIGN KEY (application_id) REFERENCES ns_application (application_id),
  CONSTRAINT ns_otp_policy_fk FOREIGN KEY (otp_policy_id) REFERENCES ns_otp_policy (otp_policy_id)
);

CREATE TABLE ns_credential_storage (
  credential_id VARCHAR(256) NOT NULL PRIMARY KEY,
  credential_definition_id INTEGER NOT NULL,
  user_id VARCHAR(256) NOT NULL,
  type VARCHAR(32) NOT NULL,
  external_reference VARCHAR(256),
  source VARCHAR(32) DEFAULT 'LOCAL',
  target VARCHAR(32) DEFAULT 'LOCAL',
  user_name VARCHAR(256),
  value VARCHAR(256) NOT NULL,
  status VARCHAR(32) NOT NULL,
  attempt_counter INTEGER DEFAULT 0 NOT NULL,
  failed_attempt_counter_soft INTEGER DEFAULT 0 NOT NULL,
  failed_attempt_counter_hard INTEGER DEFAULT 0 NOT NULL,
  encryption_algorithm VARCHAR(256),
  hashing_config_id INTEGER,
  timestamp_created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  timestamp_expires TIMESTAMP,
  timestamp_blocked TIMESTAMP,
  timestamp_last_updated TIMESTAMP,
  timestamp_last_credential_change TIMESTAMP,
  timestamp_last_username_change TIMESTAMP,
  CONSTRAINT ns_credential_definition_fk FOREIGN KEY (credential_definition_id) REFERENCES ns_credential_definition (credential_definition_id),
  CONSTRAINT ns_credential_user_fk FOREIGN KEY (user_id) REFERENCES ns_user_identity (user_id)
);

CREATE TABLE ns_credential_history (
  credential_history_id INTEGER NOT NULL PRIMARY KEY,
  credential_definition_id INTEGER NOT NULL,
  user_id VARCHAR(256) NOT NULL,
  user_name VARCHAR(256),
  value VARCHAR(256) NOT NULL,
  encryption_algorithm VARCHAR(256),
  hashing_config_id INTEGER,
  timestamp_created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT ns_credential_history_definition_fk FOREIGN KEY (credential_definition_id) REFERENCES ns_credential_definition (credential_definition_id),
  CONSTRAINT ns_credential_history_user_fk FOREIGN KEY (user_id) REFERENCES ns_user_identity (user_id)
);

CREATE TABLE ns_otp_storage (
  otp_id VARCHAR(256) NOT NULL PRIMARY KEY,
  otp_definition_id INTEGER NOT NULL,
  user_id VARCHAR(256),
  credential_definition_id INTEGER,
  operation_id VARCHAR(256),
  value VARCHAR(256),
  salt BYTEA,
  status VARCHAR(32) NOT NULL,
  otp_data TEXT,
  attempt_counter INTEGER DEFAULT 0 NOT NULL,
  failed_attempt_counter INTEGER DEFAULT 0 NOT NULL,
  encryption_algorithm VARCHAR(256),
  timestamp_created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  timestamp_verified TIMESTAMP,
  timestamp_blocked TIMESTAMP,
  timestamp_expires TIMESTAMP,
  CONSTRAINT ns_otp_definition_fk FOREIGN KEY (otp_definition_id) REFERENCES ns_otp_definition (otp_definition_id)
);

CREATE TABLE ns_operation (
  operation_id VARCHAR(256) PRIMARY KEY NOT NULL,
  operation_name VARCHAR(32) NOT NULL,
  operation_data TEXT NOT NULL,
  operation_form_data TEXT,
  application_id VARCHAR(256),
  application_name VARCHAR(256),
  application_description VARCHAR(256),
  application_original_scopes VARCHAR(256),
  application_extras TEXT,
  user_id VARCHAR(256),
  organization_id VARCHAR(256),
  user_account_status VARCHAR(32),
  external_operation_name VARCHAR(32),
  external_transaction_id VARCHAR(256),
  result VARCHAR(32),
  timestamp_created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  timestamp_expires TIMESTAMP,
  CONSTRAINT ns_operation_organization_fk FOREIGN KEY (organization_id) REFERENCES ns_organization (organization_id),
  CONSTRAINT ns_operation_config_fk FOREIGN KEY (operation_name) REFERENCES ns_operation_config (operation_name)
);

CREATE TABLE ns_authentication (
  authentication_id VARCHAR(256) NOT NULL PRIMARY KEY,
  user_id VARCHAR(256),
  type VARCHAR(32) NOT NULL,
  credential_id VARCHAR(256),
  otp_id VARCHAR(256),
  operation_id VARCHAR(256),
  result VARCHAR(32) NOT NULL,
  result_credential VARCHAR(32),
  result_otp VARCHAR(32),
  timestamp_created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT ns_auth_credential_fk FOREIGN KEY (credential_id) REFERENCES ns_credential_storage (credential_id),
  CONSTRAINT ns_auth_otp_fk FOREIGN KEY (otp_id) REFERENCES ns_otp_storage (otp_id),
  CONSTRAINT ns_auth_operation_fk FOREIGN KEY (operation_id) REFERENCES ns_operation (operation_id)
);

CREATE TABLE ns_operation_history (
  operation_id VARCHAR(256) NOT NULL,
  result_id INTEGER NOT NULL,
  request_auth_method VARCHAR(32) NOT NULL,
  request_auth_instruments VARCHAR(256),
  request_auth_step_result VARCHAR(32) NOT NULL,
  request_params VARCHAR(4000),
  response_result VARCHAR(32) NOT NULL,
  response_result_description VARCHAR(256),
  response_steps VARCHAR(4000),
  response_timestamp_created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  response_timestamp_expires TIMESTAMP,
  chosen_auth_method VARCHAR(32),
  mobile_token_active BOOLEAN DEFAULT FALSE NOT NULL,
  authentication_id VARCHAR(256),
  pa_operation_id VARCHAR(256),
  pa_auth_context VARCHAR(256),
  CONSTRAINT ns_history_pk PRIMARY KEY (operation_id, result_id),
  CONSTRAINT ns_history_operation_fk FOREIGN KEY (operation_id) REFERENCES ns_operation (operation_id),
  CONSTRAINT ns_history_auth_method_fk FOREIGN KEY (request_auth_method) REFERENCES ns_auth_method (auth_method),
  CONSTRAINT ns_history_chosen_method_fk FOREIGN KEY (chosen_auth_method) REFERENCES ns_auth_method (auth_method),
  CONSTRAINT ns_history_authentication_fk FOREIGN KEY (authentication_id) REFERENCES ns_authentication (authentication_id)
);

CREATE TABLE ns_operation_afs (
  afs_action_id INTEGER PRIMARY KEY NOT NULL,
  operation_id VARCHAR(256) NOT NULL,
  request_afs_action VARCHAR(256) NOT NULL,
  request_step_index INTEGER NOT NULL,
  request_afs_extras VARCHAR(256),
  response_afs_apply BOOLEAN DEFAULT FALSE NOT NULL,
  response_afs_label VARCHAR(256),
  response_afs_extras VARCHAR(256),
  timestamp_created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT operation_afs_fk FOREIGN KEY (operation_id) REFERENCES ns_operation (operation_id)
);

CREATE TABLE ns_user_prefs (
  user_id VARCHAR(256) PRIMARY KEY NOT NULL,
  auth_method_1 BOOLEAN DEFAULT FALSE,
  auth_method_2 BOOLEAN DEFAULT FALSE,
  auth_method_3 BOOLEAN DEFAULT FALSE,
  auth_method_4 BOOLEAN DEFAULT FALSE,
  auth_method_5 BOOLEAN DEFAULT FALSE,
  auth_method_1_config VARCHAR(256),
  auth_method_2_config VARCHAR(256),
  auth_method_3_config VARCHAR(256),
  auth_method_4_config VARCHAR(256),
  auth_method_5_config VARCHAR(256)
);

CREATE TABLE IF NOT EXISTS audit_log (
  audit_log_id VARCHAR(36) PRIMARY KEY,
  application_name VARCHAR(256) NOT NULL,
  audit_level VARCHAR(32) NOT NULL,
  audit_type VARCHAR(256),
  timestamp_created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  message TEXT NOT NULL,
  exception_message TEXT,
  stack_trace TEXT,
  param TEXT,
  calling_class VARCHAR(256) NOT NULL,
  thread_name VARCHAR(256) NOT NULL,
  version VARCHAR(256),
  build_time TIMESTAMP,
  subject_id VARCHAR(256)
);

CREATE TABLE IF NOT EXISTS audit_param (
  audit_log_id VARCHAR(36),
  timestamp_created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  param_key VARCHAR(256),
  param_value VARCHAR(4000)
);

CREATE INDEX ns_operation_pending ON ns_operation (user_id, result);
CREATE UNIQUE INDEX ns_operation_afs_unique ON ns_operation_afs (operation_id, request_afs_action, request_step_index);
CREATE UNIQUE INDEX ns_application_name ON ns_application (name);
CREATE UNIQUE INDEX ns_credential_policy_name ON ns_credential_policy (name);
CREATE UNIQUE INDEX ns_otp_policy_name ON ns_otp_policy (name);
CREATE INDEX ns_user_contact_user_id ON ns_user_contact (user_id);
CREATE UNIQUE INDEX ns_user_contact_unique ON ns_user_contact (user_id, name, type);
CREATE INDEX ns_user_identity_status ON ns_user_identity (status);
CREATE INDEX ns_user_identity_created ON ns_user_identity (timestamp_created);
CREATE INDEX ns_user_identity_history_user ON ns_user_identity_history (user_id);
CREATE INDEX ns_user_identity_history_created ON ns_user_identity_history (timestamp_created);
CREATE UNIQUE INDEX ns_role_name ON ns_role (name);
CREATE INDEX ns_user_role_user_id ON ns_user_role (user_id);
CREATE INDEX ns_user_role_role_id ON ns_user_role (role_id);
CREATE INDEX ns_user_alias_user_id ON ns_user_alias (user_id);
CREATE UNIQUE INDEX ns_credential_definition_name ON ns_credential_definition (name);
CREATE UNIQUE INDEX ns_otp_definition_name ON ns_otp_definition (name);
CREATE INDEX ns_credential_storage_user_id ON ns_credential_storage (user_id);
CREATE INDEX ns_credential_storage_status ON ns_credential_storage (status);
CREATE UNIQUE INDEX ns_credential_storage_query1 ON ns_credential_storage (credential_definition_id, user_name);
CREATE UNIQUE INDEX ns_credential_storage_query2 ON ns_credential_storage (user_id, credential_definition_id);
CREATE INDEX ns_credential_storage_query3 ON ns_credential_storage (credential_definition_id, status);
CREATE INDEX ns_credential_history_user_id ON ns_credential_history (user_id);
CREATE INDEX ns_otp_storage_user_id ON ns_otp_storage (user_id);
CREATE INDEX ns_otp_storage_user_id_status ON ns_otp_storage (user_id, status);
CREATE INDEX ns_otp_storage_operation_id ON ns_otp_storage (operation_id);
CREATE INDEX ns_authentication_user_id ON ns_authentication (user_id);
CREATE INDEX ns_authentication_operation_id ON ns_authentication (operation_id);
CREATE INDEX ns_authentication_timestamp_created ON ns_authentication (timestamp_created);
CREATE UNIQUE INDEX ns_hashing_config_name ON ns_hashing_config (name);
CREATE UNIQUE INDEX ns_user_alias_unique ON ns_user_alias (user_id, name);
CREATE UNIQUE INDEX ns_user_role_unique ON ns_user_role (user_id, role_id);
CREATE INDEX IF NOT EXISTS audit_log_timestamp ON audit_log (timestamp_created);
CREATE INDEX IF NOT EXISTS audit_log_application ON audit_log (application_name);
CREATE INDEX IF NOT EXISTS audit_log_level ON audit_log (audit_level);
CREATE INDEX IF NOT EXISTS audit_log_type ON audit_log (audit_type);
CREATE INDEX IF NOT EXISTS audit_param_log ON audit_param (audit_log_id);
CREATE INDEX IF NOT EXISTS audit_param_timestamp ON audit_param (timestamp_created);
CREATE INDEX IF NOT EXISTS audit_param_key ON audit_param (param_key);
CREATE INDEX IF NOT EXISTS audit_param_value ON audit_param (param_value);
CREATE INDEX IF NOT EXISTS audit_log_subject_id_idx ON audit_log (subject_id);

-- Foreign keys for user identity, to be used only when all user identities are stored in Next Step
-- ALTER TABLE ns_operation ADD CONSTRAINT ns_operation_user_fk FOREIGN KEY (user_id) REFERENCES ns_user_identity (user_id);
-- ALTER TABLE ns_user_prefs ADD CONSTRAINT ns_user_prefs_fk FOREIGN KEY (user_id) REFERENCES ns_user_identity (user_id);
-- ALTER TABLE ns_otp_storage ADD CONSTRAINT ns_otp_user_fk FOREIGN KEY (user_id) REFERENCES ns_user_identity (user_id);
-- ALTER TABLE ns_authentication ADD CONSTRAINT ns_auth_user_fk FOREIGN KEY (user_id) REFERENCES ns_user_identity (user_id);

CREATE TABLE IF NOT EXISTS shedlock (
  name VARCHAR(64) NOT NULL,
  lock_until TIMESTAMP WITHOUT TIME ZONE NOT NULL,
  locked_at TIMESTAMP WITHOUT TIME ZONE NOT NULL,
  locked_by VARCHAR(255) NOT NULL,
  CONSTRAINT shedlock_pkey PRIMARY KEY (name)
);

