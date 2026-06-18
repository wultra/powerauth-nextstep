--
-- Create sequences.
--
CREATE SEQUENCE ns_operation_afs_seq MINVALUE 1 MAXVALUE 9999999999999999999999999999 INCREMENT BY 1 START WITH 1 CACHE 20 NOORDER NOCYCLE;
CREATE SEQUENCE ns_application_seq MINVALUE 1 MAXVALUE 9999999999999999999999999999 INCREMENT BY 1 START WITH 1 CACHE 20 NOORDER NOCYCLE;
CREATE SEQUENCE ns_credential_policy_seq MINVALUE 1 MAXVALUE 9999999999999999999999999999 INCREMENT BY 1 START WITH 1 CACHE 20 NOORDER NOCYCLE;
CREATE SEQUENCE ns_otp_policy_seq MINVALUE 1 MAXVALUE 9999999999999999999999999999 INCREMENT BY 1 START WITH 1 CACHE 20 NOORDER NOCYCLE;
CREATE SEQUENCE ns_user_contact_seq MINVALUE 1 MAXVALUE 9999999999999999999999999999 INCREMENT BY 1 START WITH 1 CACHE 20 NOORDER NOCYCLE;
CREATE SEQUENCE ns_user_identity_history_seq MINVALUE 1 MAXVALUE 9999999999999999999999999999 INCREMENT BY 1 START WITH 1 CACHE 20 NOORDER NOCYCLE;
CREATE SEQUENCE ns_role_seq MINVALUE 1 MAXVALUE 9999999999999999999999999999 INCREMENT BY 1 START WITH 1 CACHE 20 NOORDER NOCYCLE;
CREATE SEQUENCE ns_user_role_seq MINVALUE 1 MAXVALUE 9999999999999999999999999999 INCREMENT BY 1 START WITH 1 CACHE 20 NOORDER NOCYCLE;
CREATE SEQUENCE ns_user_alias_seq MINVALUE 1 MAXVALUE 9999999999999999999999999999 INCREMENT BY 1 START WITH 1 CACHE 20 NOORDER NOCYCLE;
CREATE SEQUENCE ns_hashing_config_seq MINVALUE 1 MAXVALUE 9999999999999999999999999999 INCREMENT BY 1 START WITH 1 CACHE 20 NOORDER NOCYCLE;
CREATE SEQUENCE ns_credential_definition_seq MINVALUE 1 MAXVALUE 9999999999999999999999999999 INCREMENT BY 2 START WITH 1 CACHE 20 NOORDER NOCYCLE;
CREATE SEQUENCE ns_otp_definition_seq MINVALUE 1 MAXVALUE 9999999999999999999999999999 INCREMENT BY 2 START WITH 1 CACHE 20 NOORDER NOCYCLE;
CREATE SEQUENCE ns_credential_history_seq MINVALUE 1 MAXVALUE 9999999999999999999999999999 INCREMENT BY 1 START WITH 1 CACHE 20 NOORDER NOCYCLE;

CREATE TABLE ns_auth_method (
  auth_method VARCHAR2(32 CHAR) PRIMARY KEY NOT NULL,
  order_number INTEGER NOT NULL,
  check_user_prefs NUMBER(1) DEFAULT 0 NOT NULL,
  user_prefs_column INTEGER,
  user_prefs_default NUMBER(1) DEFAULT 0,
  check_auth_fails NUMBER(1) DEFAULT 0 NOT NULL,
  max_auth_fails INTEGER,
  has_user_interface NUMBER(1) DEFAULT 0,
  has_mobile_token NUMBER(1) DEFAULT 0,
  display_name_key VARCHAR2(32 CHAR)
);

CREATE TABLE ns_operation_config (
  operation_name VARCHAR2(32 CHAR) PRIMARY KEY NOT NULL,
  template_version VARCHAR2(1 CHAR) NOT NULL,
  template_id INTEGER NOT NULL,
  mobile_token_enabled NUMBER(1) DEFAULT 0 NOT NULL,
  mobile_token_mode VARCHAR2(256 CHAR) NOT NULL,
  afs_enabled NUMBER(1) DEFAULT 0 NOT NULL,
  afs_config_id VARCHAR2(256 CHAR),
  expiration_time INTEGER
);

CREATE TABLE ns_operation_method_config (
  operation_name VARCHAR2(32 CHAR) NOT NULL,
  auth_method VARCHAR2(32 CHAR) NOT NULL,
  max_auth_fails INTEGER NOT NULL,
  PRIMARY KEY (operation_name, auth_method),
  CONSTRAINT ns_operation_method_fk1 FOREIGN KEY (operation_name) REFERENCES ns_operation_config (operation_name),
  CONSTRAINT ns_operation_method_fk2 FOREIGN KEY (auth_method) REFERENCES ns_auth_method (auth_method)
);

CREATE TABLE ns_organization (
  organization_id VARCHAR2(256 CHAR) PRIMARY KEY NOT NULL,
  display_name_key VARCHAR2(256 CHAR),
  is_default NUMBER(1) DEFAULT 0 NOT NULL,
  order_number INTEGER NOT NULL,
  default_credential_name VARCHAR2(256 CHAR),
  default_otp_name VARCHAR2(256 CHAR)
);

CREATE TABLE ns_step_definition (
  step_definition_id INTEGER PRIMARY KEY NOT NULL,
  operation_name VARCHAR2(32 CHAR) NOT NULL,
  operation_type VARCHAR2(32 CHAR) NOT NULL,
  request_auth_method VARCHAR2(32 CHAR),
  request_auth_step_result VARCHAR2(32 CHAR),
  response_priority INTEGER NOT NULL,
  response_auth_method VARCHAR2(32 CHAR),
  response_result VARCHAR2(32 CHAR) NOT NULL,
  CONSTRAINT step_request_auth_method_fk FOREIGN KEY (request_auth_method) REFERENCES ns_auth_method (auth_method),
  CONSTRAINT step_response_auth_method_fk FOREIGN KEY (response_auth_method) REFERENCES ns_auth_method (auth_method)
);

CREATE TABLE ns_application (
  application_id NUMBER(19,0) NOT NULL PRIMARY KEY,
  name VARCHAR2(256 CHAR) NOT NULL,
  description VARCHAR2(256 CHAR),
  status VARCHAR2(32 CHAR) NOT NULL,
  timestamp_created TIMESTAMP DEFAULT sysdate,
  timestamp_last_updated TIMESTAMP
);

CREATE TABLE ns_credential_policy (
  credential_policy_id NUMBER(19,0) NOT NULL PRIMARY KEY,
  name VARCHAR2(256 CHAR) NOT NULL,
  description VARCHAR2(256 CHAR) NOT NULL,
  status VARCHAR2(32 CHAR) NOT NULL,
  username_length_min NUMBER(10,0),
  username_length_max NUMBER(10,0),
  username_allowed_pattern VARCHAR2(256 CHAR),
  credential_length_min NUMBER(10,0),
  credential_length_max NUMBER(10,0),
  limit_soft NUMBER(10,0),
  limit_hard NUMBER(10,0),
  check_history_count NUMBER(10,0) DEFAULT 0 NOT NULL,
  rotation_enabled NUMBER(1) DEFAULT 0 NOT NULL,
  rotation_days NUMBER(10,0),
  credential_temp_expiration INTEGER,
  username_gen_algorithm VARCHAR2(256 CHAR) DEFAULT 'DEFAULT' NOT NULL,
  username_gen_param VARCHAR2(4000 CHAR) NOT NULL,
  credential_gen_algorithm VARCHAR2(256 CHAR) DEFAULT 'DEFAULT' NOT NULL,
  credential_gen_param VARCHAR2(4000 CHAR) NOT NULL,
  credential_val_param VARCHAR2(4000 CHAR) NOT NULL,
  timestamp_created TIMESTAMP DEFAULT sysdate,
  timestamp_last_updated TIMESTAMP
);

CREATE TABLE ns_otp_policy (
  otp_policy_id NUMBER(19,0) NOT NULL PRIMARY KEY,
  name VARCHAR2(256 CHAR) NOT NULL,
  description VARCHAR2(256 CHAR),
  status VARCHAR2(32 CHAR) NOT NULL,
  length NUMBER(10,0) NOT NULL,
  attempt_limit NUMBER(10,0),
  expiration_time NUMBER(10,0),
  gen_algorithm VARCHAR2(256 CHAR) DEFAULT 'DEFAULT' NOT NULL,
  gen_param VARCHAR2(4000 CHAR) NOT NULL,
  timestamp_created TIMESTAMP DEFAULT sysdate,
  timestamp_last_updated TIMESTAMP
);

CREATE TABLE ns_user_identity (
  user_id VARCHAR2(256 CHAR) NOT NULL PRIMARY KEY,
  status VARCHAR2(32 CHAR) NOT NULL,
  extras CLOB,
  timestamp_created TIMESTAMP DEFAULT sysdate,
  timestamp_last_updated TIMESTAMP
);

CREATE TABLE ns_user_contact (
  user_contact_id NUMBER(19,0) NOT NULL PRIMARY KEY,
  user_id VARCHAR2(256 CHAR) NOT NULL,
  name VARCHAR2(256 CHAR) NOT NULL,
  type VARCHAR2(32 CHAR) NOT NULL,
  value VARCHAR2(256 CHAR) NOT NULL,
  is_primary NUMBER(1) DEFAULT 0 NOT NULL,
  timestamp_created TIMESTAMP DEFAULT sysdate,
  timestamp_last_updated TIMESTAMP,
  CONSTRAINT ns_user_contact_fk FOREIGN KEY (user_id) REFERENCES ns_user_identity (user_id)
);

CREATE TABLE ns_user_identity_history (
  user_identity_history_id NUMBER(19,0) NOT NULL PRIMARY KEY,
  user_id VARCHAR2(256 CHAR) NOT NULL,
  status VARCHAR2(32 CHAR) NOT NULL,
  roles VARCHAR2(256 CHAR),
  extras CLOB,
  timestamp_created TIMESTAMP DEFAULT sysdate,
  CONSTRAINT ns_user_identity_history_fk FOREIGN KEY (user_id) REFERENCES ns_user_identity (user_id)
);

CREATE TABLE ns_role (
  role_id NUMBER(19,0) NOT NULL PRIMARY KEY,
  name VARCHAR2(256 CHAR) NOT NULL,
  description VARCHAR2(256 CHAR),
  timestamp_created TIMESTAMP DEFAULT sysdate,
  timestamp_last_updated TIMESTAMP
);

CREATE TABLE ns_user_role (
  user_role_id NUMBER(19,0) NOT NULL PRIMARY KEY,
  user_id VARCHAR2(256 CHAR) NOT NULL,
  role_id NUMBER(19,0) NOT NULL,
  status VARCHAR2(32 CHAR) NOT NULL,
  timestamp_created TIMESTAMP DEFAULT sysdate,
  timestamp_last_updated TIMESTAMP,
  CONSTRAINT ns_role_identity_fk FOREIGN KEY (user_id) REFERENCES ns_user_identity (user_id),
  CONSTRAINT ns_user_role_fk FOREIGN KEY (role_id) REFERENCES ns_role (role_id)
);

CREATE TABLE ns_user_alias (
  user_alias_id NUMBER(19,0) NOT NULL PRIMARY KEY,
  user_id VARCHAR2(256 CHAR) NOT NULL,
  name VARCHAR2(256 CHAR) NOT NULL,
  value VARCHAR2(256 CHAR) NOT NULL,
  status VARCHAR2(32 CHAR) NOT NULL,
  extras CLOB,
  timestamp_created TIMESTAMP DEFAULT sysdate,
  timestamp_last_updated TIMESTAMP,
  CONSTRAINT ns_user_alias_fk FOREIGN KEY (user_id) REFERENCES ns_user_identity (user_id)
);

CREATE TABLE ns_hashing_config (
  hashing_config_id NUMBER(19,0) NOT NULL PRIMARY KEY,
  name VARCHAR2(256 CHAR) NOT NULL,
  algorithm VARCHAR2(256 CHAR) NOT NULL,
  status VARCHAR2(32 CHAR) NOT NULL,
  parameters VARCHAR2(256 CHAR),
  timestamp_created TIMESTAMP DEFAULT sysdate,
  timestamp_last_updated TIMESTAMP
);

CREATE TABLE ns_credential_definition (
  credential_definition_id NUMBER(19,0) NOT NULL PRIMARY KEY,
  name VARCHAR2(256 CHAR) NOT NULL,
  description VARCHAR2(256 CHAR),
  application_id NUMBER(19,0) NOT NULL,
  organization_id VARCHAR2(256 CHAR),
  credential_policy_id NUMBER(19,0) NOT NULL,
  category VARCHAR2(32 CHAR) NOT NULL,
  encryption_enabled NUMBER(1) DEFAULT 0 NOT NULL,
  encryption_algorithm VARCHAR2(256 CHAR) NOT NULL,
  hashing_enabled NUMBER(1) DEFAULT 0 NOT NULL,
  hashing_config_id NUMBER(19,0),
  e2e_encryption_enabled NUMBER(1) DEFAULT 0 NOT NULL,
  e2e_encryption_algorithm VARCHAR2(256 CHAR),
  e2e_encryption_transform VARCHAR2(256 CHAR),
  e2e_encryption_temporary NUMBER(1) DEFAULT 0 NOT NULL,
  data_adapter_proxy_enabled NUMBER(1) DEFAULT 0 NOT NULL,
  status VARCHAR2(32 CHAR) NOT NULL,
  parameters VARCHAR2(256 CHAR),
  timestamp_created TIMESTAMP DEFAULT sysdate,
  timestamp_last_updated TIMESTAMP,
  CONSTRAINT ns_credential_application_fk FOREIGN KEY (application_id) REFERENCES ns_application (application_id),
  CONSTRAINT ns_application_organization_fk FOREIGN KEY (organization_id) REFERENCES ns_organization (organization_id),
  CONSTRAINT ns_credential_policy_fk FOREIGN KEY (credential_policy_id) REFERENCES ns_credential_policy (credential_policy_id),
  CONSTRAINT ns_credential_hash_fk FOREIGN KEY (hashing_config_id) REFERENCES ns_hashing_config (hashing_config_id)
);

CREATE TABLE ns_otp_definition (
  otp_definition_id NUMBER(19,0) NOT NULL PRIMARY KEY,
  name VARCHAR2(256 CHAR) NOT NULL,
  description VARCHAR2(256 CHAR),
  application_id NUMBER(19,0) NOT NULL,
  otp_policy_id NUMBER(19,0) NOT NULL,
  encryption_enabled NUMBER(1) DEFAULT 0 NOT NULL,
  encryption_algorithm VARCHAR2(256 CHAR),
  data_adapter_proxy_enabled NUMBER(1) DEFAULT 0 NOT NULL,
  status VARCHAR2(32 CHAR) NOT NULL,
  timestamp_created TIMESTAMP DEFAULT sysdate,
  timestamp_last_updated TIMESTAMP,
  CONSTRAINT ns_otp_application_fk FOREIGN KEY (application_id) REFERENCES ns_application (application_id),
  CONSTRAINT ns_otp_policy_fk FOREIGN KEY (otp_policy_id) REFERENCES ns_otp_policy (otp_policy_id)
);

CREATE TABLE ns_credential_storage (
  credential_id VARCHAR2(256 CHAR) NOT NULL PRIMARY KEY,
  credential_definition_id NUMBER(19,0) NOT NULL,
  user_id VARCHAR2(256 CHAR) NOT NULL,
  type VARCHAR2(32 CHAR) NOT NULL,
  external_reference VARCHAR2(256 CHAR),
  source VARCHAR2(32 CHAR) DEFAULT 'LOCAL',
  target VARCHAR2(32 CHAR) DEFAULT 'LOCAL',
  user_name VARCHAR2(256 CHAR),
  value VARCHAR2(256 CHAR) NOT NULL,
  status VARCHAR2(32 CHAR) NOT NULL,
  attempt_counter NUMBER(19,0) DEFAULT 0 NOT NULL,
  failed_attempt_counter_soft NUMBER(19,0) DEFAULT 0 NOT NULL,
  failed_attempt_counter_hard NUMBER(19,0) DEFAULT 0 NOT NULL,
  encryption_algorithm VARCHAR2(256 CHAR),
  hashing_config_id NUMBER(19,0),
  timestamp_created TIMESTAMP DEFAULT sysdate,
  timestamp_expires TIMESTAMP,
  timestamp_blocked TIMESTAMP,
  timestamp_last_updated TIMESTAMP,
  timestamp_last_credential_change TIMESTAMP,
  timestamp_last_username_change TIMESTAMP,
  CONSTRAINT ns_credential_definition_fk FOREIGN KEY (credential_definition_id) REFERENCES ns_credential_definition (credential_definition_id),
  CONSTRAINT ns_credential_user_fk FOREIGN KEY (user_id) REFERENCES ns_user_identity (user_id)
);

CREATE TABLE ns_credential_history (
  credential_history_id NUMBER(19,0) NOT NULL PRIMARY KEY,
  credential_definition_id NUMBER(19,0) NOT NULL,
  user_id VARCHAR2(256 CHAR) NOT NULL,
  user_name VARCHAR2(256 CHAR),
  value VARCHAR2(256 CHAR) NOT NULL,
  encryption_algorithm VARCHAR2(256 CHAR),
  hashing_config_id NUMBER(19,0),
  timestamp_created TIMESTAMP DEFAULT sysdate,
  CONSTRAINT ns_credential_history_definition_fk FOREIGN KEY (credential_definition_id) REFERENCES ns_credential_definition (credential_definition_id),
  CONSTRAINT ns_credential_history_user_fk FOREIGN KEY (user_id) REFERENCES ns_user_identity (user_id)
);

CREATE TABLE ns_otp_storage (
  otp_id VARCHAR2(256 CHAR) NOT NULL PRIMARY KEY,
  otp_definition_id NUMBER(19,0) NOT NULL,
  user_id VARCHAR2(256 CHAR),
  credential_definition_id NUMBER(19,0),
  operation_id VARCHAR2(256 CHAR),
  value VARCHAR2(256 CHAR),
  salt BLOB,
  status VARCHAR2(32 CHAR) NOT NULL,
  otp_data CLOB,
  attempt_counter NUMBER(19,0) DEFAULT 0 NOT NULL,
  failed_attempt_counter NUMBER(19,0) DEFAULT 0 NOT NULL,
  encryption_algorithm VARCHAR2(256 CHAR),
  timestamp_created TIMESTAMP DEFAULT sysdate,
  timestamp_verified TIMESTAMP,
  timestamp_blocked TIMESTAMP,
  timestamp_expires TIMESTAMP,
  CONSTRAINT ns_otp_definition_fk FOREIGN KEY (otp_definition_id) REFERENCES ns_otp_definition (otp_definition_id)
);

CREATE TABLE ns_operation (
  operation_id VARCHAR2(256 CHAR) PRIMARY KEY NOT NULL,
  operation_name VARCHAR2(32 CHAR) NOT NULL,
  operation_data CLOB NOT NULL,
  operation_form_data CLOB,
  application_id VARCHAR2(256 CHAR),
  application_name VARCHAR2(256 CHAR),
  application_description VARCHAR2(256 CHAR),
  application_original_scopes VARCHAR2(256 CHAR),
  application_extras CLOB,
  user_id VARCHAR2(256 CHAR),
  organization_id VARCHAR2(256 CHAR),
  user_account_status VARCHAR2(32 CHAR),
  external_operation_name VARCHAR2(32 CHAR),
  external_transaction_id VARCHAR2(256 CHAR),
  result VARCHAR2(32 CHAR),
  timestamp_created TIMESTAMP DEFAULT sysdate,
  timestamp_expires TIMESTAMP,
  CONSTRAINT ns_operation_organization_fk FOREIGN KEY (organization_id) REFERENCES ns_organization (organization_id),
  CONSTRAINT ns_operation_config_fk FOREIGN KEY (operation_name) REFERENCES ns_operation_config (operation_name)
);

CREATE TABLE ns_authentication (
  authentication_id VARCHAR2(256 CHAR) NOT NULL PRIMARY KEY,
  user_id VARCHAR2(256 CHAR),
  type VARCHAR2(32 CHAR) NOT NULL,
  credential_id VARCHAR2(256 CHAR),
  otp_id VARCHAR2(256 CHAR),
  operation_id VARCHAR2(256 CHAR),
  result VARCHAR2(32 CHAR) NOT NULL,
  result_credential VARCHAR2(32 CHAR),
  result_otp VARCHAR2(32 CHAR),
  timestamp_created TIMESTAMP DEFAULT sysdate,
  CONSTRAINT ns_auth_credential_fk FOREIGN KEY (credential_id) REFERENCES ns_credential_storage (credential_id),
  CONSTRAINT ns_auth_otp_fk FOREIGN KEY (otp_id) REFERENCES ns_otp_storage (otp_id),
  CONSTRAINT ns_auth_operation_fk FOREIGN KEY (operation_id) REFERENCES ns_operation (operation_id)
);

CREATE TABLE ns_operation_history (
  operation_id VARCHAR2(256 CHAR) NOT NULL,
  result_id INTEGER NOT NULL,
  request_auth_method VARCHAR2(32 CHAR) NOT NULL,
  request_auth_instruments VARCHAR2(256 CHAR),
  request_auth_step_result VARCHAR2(32 CHAR) NOT NULL,
  request_params VARCHAR2(4000 CHAR),
  response_result VARCHAR2(32 CHAR) NOT NULL,
  response_result_description VARCHAR2(256 CHAR),
  response_steps VARCHAR2(4000 CHAR),
  response_timestamp_created TIMESTAMP DEFAULT sysdate,
  response_timestamp_expires TIMESTAMP,
  chosen_auth_method VARCHAR2(32 CHAR),
  mobile_token_active NUMBER(1) DEFAULT 0 NOT NULL,
  authentication_id VARCHAR2(256 CHAR),
  pa_operation_id VARCHAR2(256 CHAR),
  pa_auth_context VARCHAR2(256 CHAR),
  CONSTRAINT ns_history_pk PRIMARY KEY (operation_id, result_id),
  CONSTRAINT ns_history_operation_fk FOREIGN KEY (operation_id) REFERENCES ns_operation (operation_id),
  CONSTRAINT ns_history_auth_method_fk FOREIGN KEY (request_auth_method) REFERENCES ns_auth_method (auth_method),
  CONSTRAINT ns_history_chosen_method_fk FOREIGN KEY (chosen_auth_method) REFERENCES ns_auth_method (auth_method),
  CONSTRAINT ns_history_authentication_fk FOREIGN KEY (authentication_id) REFERENCES ns_authentication (authentication_id)
);

CREATE TABLE ns_operation_afs (
  afs_action_id INTEGER PRIMARY KEY NOT NULL,
  operation_id VARCHAR2(256 CHAR) NOT NULL,
  request_afs_action VARCHAR2(256 CHAR) NOT NULL,
  request_step_index INTEGER NOT NULL,
  request_afs_extras VARCHAR2(256 CHAR),
  response_afs_apply NUMBER(1) DEFAULT 0 NOT NULL,
  response_afs_label VARCHAR2(256 CHAR),
  response_afs_extras VARCHAR2(256 CHAR),
  timestamp_created TIMESTAMP DEFAULT sysdate,
  CONSTRAINT ns_operation_afs_fk FOREIGN KEY (operation_id) REFERENCES ns_operation (operation_id)
);

CREATE TABLE ns_user_prefs (
  user_id VARCHAR2(256 CHAR) PRIMARY KEY NOT NULL,
  auth_method_1 NUMBER(1) DEFAULT 0,
  auth_method_2 NUMBER(1) DEFAULT 0,
  auth_method_3 NUMBER(1) DEFAULT 0,
  auth_method_4 NUMBER(1) DEFAULT 0,
  auth_method_5 NUMBER(1) DEFAULT 0,
  auth_method_1_config VARCHAR2(256 CHAR),
  auth_method_2_config VARCHAR2(256 CHAR),
  auth_method_3_config VARCHAR2(256 CHAR),
  auth_method_4_config VARCHAR2(256 CHAR),
  auth_method_5_config VARCHAR2(256 CHAR)
);

BEGIN EXECUTE IMMEDIATE 'CREATE TABLE audit_log (
  audit_log_id VARCHAR2(36 CHAR) PRIMARY KEY,
  application_name VARCHAR2(256 CHAR) NOT NULL,
  audit_level VARCHAR2(32 CHAR) NOT NULL,
  audit_type VARCHAR2(256 CHAR),
  timestamp_created TIMESTAMP DEFAULT sysdate,
  message CLOB NOT NULL,
  exception_message CLOB,
  stack_trace CLOB,
  param CLOB,
  calling_class VARCHAR2(256 CHAR) NOT NULL,
  thread_name VARCHAR2(256 CHAR) NOT NULL,
  version VARCHAR2(256 CHAR),
  build_time TIMESTAMP,
  subject_id VARCHAR2(256 CHAR)
)';
EXCEPTION WHEN OTHERS THEN IF SQLCODE != -955 THEN RAISE; END IF; END;
/

BEGIN EXECUTE IMMEDIATE 'CREATE TABLE audit_param (
  audit_log_id VARCHAR2(36 CHAR),
  timestamp_created TIMESTAMP DEFAULT sysdate,
  param_key VARCHAR2(256 CHAR),
  param_value VARCHAR2(4000 CHAR)
)';
EXCEPTION WHEN OTHERS THEN IF SQLCODE != -955 THEN RAISE; END IF; END;
/

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
CREATE INDEX ns_user_role_role ON ns_user_role (role_id);
CREATE INDEX ns_user_alias_user_id ON ns_user_alias (user_id);
CREATE UNIQUE INDEX ns_credential_definition_name ON ns_credential_definition (name);
CREATE UNIQUE INDEX ns_otp_definition_name ON ns_otp_definition (name);
CREATE INDEX ns_credential_storage_user_id ON ns_credential_storage (user_id);
CREATE INDEX ns_credential_storage_status ON ns_credential_storage (status);
CREATE UNIQUE INDEX ns_credential_storage_query1 ON ns_credential_storage (CASE WHEN user_name IS NOT NULL THEN credential_definition_id || ''&'' || user_name END);
CREATE INDEX ns_credential_storage_query1_perf ON ns_credential_storage (credential_definition_id, user_name);
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

BEGIN EXECUTE IMMEDIATE 'CREATE INDEX audit_log_timestamp ON audit_log (timestamp_created)';
EXCEPTION WHEN OTHERS THEN IF SQLCODE != -955 THEN RAISE; END IF; END;
/

BEGIN EXECUTE IMMEDIATE 'CREATE INDEX audit_log_application ON audit_log (application_name)';
EXCEPTION WHEN OTHERS THEN IF SQLCODE != -955 THEN RAISE; END IF; END;
/

BEGIN EXECUTE IMMEDIATE 'CREATE INDEX audit_log_level ON audit_log (audit_level)';
EXCEPTION WHEN OTHERS THEN IF SQLCODE != -955 THEN RAISE; END IF; END;
/

BEGIN EXECUTE IMMEDIATE 'CREATE INDEX audit_log_type ON audit_log (audit_type)';
EXCEPTION WHEN OTHERS THEN IF SQLCODE != -955 THEN RAISE; END IF; END;
/

BEGIN EXECUTE IMMEDIATE 'CREATE INDEX audit_param_log ON audit_param (audit_log_id)';
EXCEPTION WHEN OTHERS THEN IF SQLCODE != -955 THEN RAISE; END IF; END;
/

BEGIN EXECUTE IMMEDIATE 'CREATE INDEX audit_param_timestamp ON audit_param (timestamp_created)';
EXCEPTION WHEN OTHERS THEN IF SQLCODE != -955 THEN RAISE; END IF; END;
/

BEGIN EXECUTE IMMEDIATE 'CREATE INDEX audit_param_key ON audit_param (param_key)';
EXCEPTION WHEN OTHERS THEN IF SQLCODE != -955 THEN RAISE; END IF; END;
/

BEGIN EXECUTE IMMEDIATE 'CREATE INDEX audit_param_value ON audit_param (param_value)';
EXCEPTION WHEN OTHERS THEN IF SQLCODE != -955 THEN RAISE; END IF; END;
/

BEGIN EXECUTE IMMEDIATE 'CREATE INDEX audit_log_subject_id_idx ON audit_log (subject_id)';
EXCEPTION WHEN OTHERS THEN IF SQLCODE != -955 THEN RAISE; END IF; END;
/

-- Foreign keys for user identity, to be used only when all user identities are stored in Next Step
-- ALTER TABLE ns_operation ADD CONSTRAINT ns_operation_user_fk FOREIGN KEY (user_id) REFERENCES ns_user_identity (user_id);
-- ALTER TABLE ns_user_prefs ADD CONSTRAINT ns_user_prefs_fk FOREIGN KEY (user_id) REFERENCES ns_user_identity (user_id);
-- ALTER TABLE ns_otp_storage ADD CONSTRAINT ns_otp_user_fk FOREIGN KEY (user_id) REFERENCES ns_user_identity (user_id);
-- ALTER TABLE ns_authentication ADD CONSTRAINT ns_auth_user_fk FOREIGN KEY (user_id) REFERENCES ns_user_identity (user_id);

CREATE TABLE shedlock (
  name VARCHAR2(64) NOT NULL,
  lock_until TIMESTAMP NOT NULL,
  locked_at TIMESTAMP NOT NULL,
  locked_by VARCHAR2(255) NOT NULL,
  CONSTRAINT PK_SHEDLOCK PRIMARY KEY (name)
);

