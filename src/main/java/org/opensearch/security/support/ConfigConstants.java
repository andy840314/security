/*
 * Copyright 2015-2018 _floragunn_ GmbH
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Portions Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

package org.opensearch.security.support;

import org.opensearch.security.auditlog.impl.AuditCategory;

import org.opensearch.common.settings.Settings;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;

public class ConfigConstants {


    public static final String SECURITY_CONFIG_PREFIX = "_opendistro_security_";

    public static final String SECURITY_CHANNEL_TYPE = SECURITY_CONFIG_PREFIX+"channel_type";

    public static final String SECURITY_ORIGIN = SECURITY_CONFIG_PREFIX+"origin";
    public static final String SECURITY_ORIGIN_HEADER = SECURITY_CONFIG_PREFIX+"origin_header";

    public static final String SECURITY_DLS_QUERY_HEADER = SECURITY_CONFIG_PREFIX+"dls_query";

    public static final String SECURITY_FLS_FIELDS_HEADER = SECURITY_CONFIG_PREFIX+"fls_fields";
    
    public static final String SECURITY_MASKED_FIELD_HEADER = SECURITY_CONFIG_PREFIX+"masked_fields";

    public static final String SECURITY_DLS_QUERY_CCS = SECURITY_CONFIG_PREFIX+"dls_query_ccs";

    public static final String SECURITY_FLS_FIELDS_CCS = SECURITY_CONFIG_PREFIX+"fls_fields_ccs";

    public static final String SECURITY_MASKED_FIELD_CCS = SECURITY_CONFIG_PREFIX+"masked_fields_ccs";

    public static final String SECURITY_CONF_REQUEST_HEADER = SECURITY_CONFIG_PREFIX+"conf_request";

    public static final String SECURITY_REMOTE_ADDRESS = SECURITY_CONFIG_PREFIX+"remote_address";
    public static final String SECURITY_REMOTE_ADDRESS_HEADER = SECURITY_CONFIG_PREFIX+"remote_address_header";
    
    public static final String SECURITY_INITIAL_ACTION_CLASS_HEADER = SECURITY_CONFIG_PREFIX+"initial_action_class_header";

    /**
     * Set by SSL plugin for https requests only
     */
    public static final String SECURITY_SSL_PEER_CERTIFICATES = SECURITY_CONFIG_PREFIX+"ssl_peer_certificates";

    /**
     * Set by SSL plugin for https requests only
     */
    public static final String SECURITY_SSL_PRINCIPAL = SECURITY_CONFIG_PREFIX+"ssl_principal";

    /**
     * If this is set to TRUE then the request comes from a Server Node (fully trust)
     * Its expected that there is a _opendistro_security_user attached as header
     */
    public static final String SECURITY_SSL_TRANSPORT_INTERCLUSTER_REQUEST = SECURITY_CONFIG_PREFIX+"ssl_transport_intercluster_request";

    public static final String SECURITY_SSL_TRANSPORT_TRUSTED_CLUSTER_REQUEST = SECURITY_CONFIG_PREFIX+"ssl_transport_trustedcluster_request";


    /**
     * Set by the SSL plugin, this is the peer node certificate on the transport layer
     */
    public static final String SECURITY_SSL_TRANSPORT_PRINCIPAL = SECURITY_CONFIG_PREFIX+"ssl_transport_principal";

    public static final String SECURITY_USER = SECURITY_CONFIG_PREFIX+"user";
    public static final String SECURITY_USER_HEADER = SECURITY_CONFIG_PREFIX+"user_header";

    public static final String SECURITY_USER_INFO_THREAD_CONTEXT = SECURITY_CONFIG_PREFIX + "user_info";

    public static final String SECURITY_INJECTED_USER = "injected_user";
    public static final String SECURITY_INJECTED_USER_HEADER = "injected_user_header";

    public static final String SECURITY_XFF_DONE = SECURITY_CONFIG_PREFIX+"xff_done";

    public static final String SSO_LOGOUT_URL = SECURITY_CONFIG_PREFIX+"sso_logout_url";

    
    public static final String SECURITY_DEFAULT_CONFIG_INDEX = ".opendistro_security";

    public static final String SECURITY_ENABLE_SNAPSHOT_RESTORE_PRIVILEGE = "plugins.security.enable_snapshot_restore_privilege";//need to add default in Settings class
    public static final boolean SECURITY_DEFAULT_ENABLE_SNAPSHOT_RESTORE_PRIVILEGE = true;

    public static final String SECURITY_CHECK_SNAPSHOT_RESTORE_WRITE_PRIVILEGES = "plugins.security.check_snapshot_restore_write_privileges";//need to add default in Settings class
    public static final boolean SECURITY_DEFAULT_CHECK_SNAPSHOT_RESTORE_WRITE_PRIVILEGES = true;
    public static final Set<String> SECURITY_SNAPSHOT_RESTORE_NEEDED_WRITE_PRIVILEGES = Collections.unmodifiableSet(
            new HashSet<String>(Arrays.asList(
                    "indices:admin/create",
                    "indices:data/write/index"
                    // "indices:data/write/bulk"
              )));

    public static final String SECURITY_INTERCLUSTER_REQUEST_EVALUATOR_CLASS = "plugins.security.cert.intercluster_request_evaluator_class";//need to deal with default //did not add settings, always default
    public static final String SECURITY_ACTION_NAME = SECURITY_CONFIG_PREFIX+"action_name";


    public static final String SECURITY_AUTHCZ_ADMIN_DN = "plugins.security.authcz.admin_dn";//default value same
    public static final String SECURITY_CONFIG_INDEX_NAME = "plugins.security.config_index_name";//need to add default in Settings class
    public static final String SECURITY_AUTHCZ_IMPERSONATION_DN = "plugins.security.authcz.impersonation_dn";//problem //add settings.getByPrefix for old settings
    public static final String SECURITY_AUTHCZ_REST_IMPERSONATION_USERS="plugins.security.authcz.rest_impersonation_user";//problem
    
    public static final String SECURITY_AUDIT_TYPE_DEFAULT = "plugins.security.audit.type";//problem // can not fallback 
    public static final String SECURITY_AUDIT_CONFIG_DEFAULT = "plugins.security.audit.config";//problem // can not fallback
    public static final String SECURITY_AUDIT_CONFIG_ROUTES = "plugins.security.audit.routes";// no default value
    public static final String SECURITY_AUDIT_CONFIG_ENDPOINTS = "plugins.security.audit.endpoints";//problem //group setting issue
    public static final String SECURITY_AUDIT_THREADPOOL_SIZE = "plugins.security.audit.threadpool.size";//default value same
    public static final String SECURITY_AUDIT_THREADPOOL_MAX_QUEUE_LEN = "plugins.security.audit.threadpool.max_queue_len";//default value same
    public static final String SECURITY_AUDIT_LOG_REQUEST_BODY = "plugins.security.audit.log_request_body";//default value same
    public static final String SECURITY_AUDIT_RESOLVE_INDICES = "plugins.security.audit.resolve_indices";//default value same
    public static final String SECURITY_AUDIT_ENABLE_REST = "plugins.security.audit.enable_rest";//default value same
    public static final String SECURITY_AUDIT_ENABLE_TRANSPORT = "plugins.security.audit.enable_transport";//default value same
    public static final String SECURITY_AUDIT_CONFIG_DISABLED_TRANSPORT_CATEGORIES = "plugins.security.audit.config.disabled_transport_categories";//problem
    public static final String SECURITY_AUDIT_CONFIG_DISABLED_REST_CATEGORIES = "plugins.security.audit.config.disabled_rest_categories";//problem
    public static final List<String> SECURITY_AUDIT_DISABLED_CATEGORIES_DEFAULT = ImmutableList.of(AuditCategory.AUTHENTICATED.toString(),
            AuditCategory.GRANTED_PRIVILEGES.toString());
    public static final String SECURITY_AUDIT_IGNORE_USERS = "plugins.security.audit.ignore_users";//default value same
    public static final String SECURITY_AUDIT_IGNORE_REQUESTS = "plugins.security.audit.ignore_requests";//default value same
    public static final String SECURITY_AUDIT_RESOLVE_BULK_REQUESTS = "plugins.security.audit.resolve_bulk_requests";//default value same
    public static final boolean SECURITY_AUDIT_SSL_VERIFY_HOSTNAMES_DEFAULT = true;
    public static final boolean SECURITY_AUDIT_SSL_ENABLE_SSL_CLIENT_AUTH_DEFAULT = false;
    public static final String SECURITY_AUDIT_EXCLUDE_SENSITIVE_HEADERS = "plugins.security.audit.exclude_sensitive_headers";//default value same
    
    public static final String SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX = "plugins.security.audit.config.";

    // Internal / External OpenSearch
    public static final String SECURITY_AUDIT_OPENSEARCH_INDEX = "index";// need to add default in Settings class
    public static final String SECURITY_AUDIT_OPENSEARCH_TYPE = "type";// need to add default in Settings class
    
    // External OpenSearch
    public static final String SECURITY_AUDIT_EXTERNAL_OPENSEARCH_HTTP_ENDPOINTS = "http_endpoints";// no default value
    public static final String SECURITY_AUDIT_EXTERNAL_OPENSEARCH_USERNAME = "username";// no default value
    public static final String SECURITY_AUDIT_EXTERNAL_OPENSEARCH_PASSWORD = "password";// no default value
    public static final String SECURITY_AUDIT_EXTERNAL_OPENSEARCH_ENABLE_SSL = "enable_ssl";//default value same
    public static final String SECURITY_AUDIT_EXTERNAL_OPENSEARCH_VERIFY_HOSTNAMES = "verify_hostnames";//default value same
    public static final String SECURITY_AUDIT_EXTERNAL_OPENSEARCH_ENABLE_SSL_CLIENT_AUTH = "enable_ssl_client_auth";//default value same
    public static final String SECURITY_AUDIT_EXTERNAL_OPENSEARCH_PEMKEY_FILEPATH = "pemkey_filepath";// no default value
    public static final String SECURITY_AUDIT_EXTERNAL_OPENSEARCH_PEMKEY_CONTENT = "pemkey_content";//problem
    public static final String SECURITY_AUDIT_EXTERNAL_OPENSEARCH_PEMKEY_PASSWORD = "pemkey_password";// no default value
    public static final String SECURITY_AUDIT_EXTERNAL_OPENSEARCH_PEMCERT_FILEPATH = "pemcert_filepath";//problem
    public static final String SECURITY_AUDIT_EXTERNAL_OPENSEARCH_PEMCERT_CONTENT = "pemcert_content";//problem
    public static final String SECURITY_AUDIT_EXTERNAL_OPENSEARCH_PEMTRUSTEDCAS_FILEPATH = "pemtrustedcas_filepath";//problem
    public static final String SECURITY_AUDIT_EXTERNAL_OPENSEARCH_PEMTRUSTEDCAS_CONTENT = "pemtrustedcas_content";//problem
    public static final String SECURITY_AUDIT_EXTERNAL_OPENSEARCH_JKS_CERT_ALIAS = "cert_alias";// need to add default in Settings class
    public static final String SECURITY_AUDIT_EXTERNAL_OPENSEARCH_ENABLED_SSL_CIPHERS = "enabled_ssl_ciphers";// default value conflict
    public static final String SECURITY_AUDIT_EXTERNAL_OPENSEARCH_ENABLED_SSL_PROTOCOLS = "enabled_ssl_protocols";// default value conflict  // change settings default

    // Webhooks    
    public static final String SECURITY_AUDIT_WEBHOOK_URL = "webhook.url"; // no default value
    public static final String SECURITY_AUDIT_WEBHOOK_FORMAT = "webhook.format"; // no default value
    public static final String SECURITY_AUDIT_WEBHOOK_SSL_VERIFY = "webhook.ssl.verify";//default value same
    public static final String SECURITY_AUDIT_WEBHOOK_PEMTRUSTEDCAS_FILEPATH = "webhook.ssl.pemtrustedcas_filepath";//problem
    public static final String SECURITY_AUDIT_WEBHOOK_PEMTRUSTEDCAS_CONTENT = "webhook.ssl.pemtrustedcas_content";//problem
    
    // Log4j
    public static final String SECURITY_AUDIT_LOG4J_LOGGER_NAME = "log4j.logger_name";//no usage
    public static final String SECURITY_AUDIT_LOG4J_LEVEL = "log4j.level";//no usage
    
    //retry
    public static final String SECURITY_AUDIT_RETRY_COUNT = "plugins.security.audit.config.retry_count";//not a opensearch.yml setting
    public static final String SECURITY_AUDIT_RETRY_DELAY_MS = "plugins.security.audit.config.retry_delay_ms";//not a opensearch.yml setting

        
    public static final String SECURITY_KERBEROS_KRB5_FILEPATH = "plugins.security.kerberos.krb5_filepath"; //no usage
    public static final String SECURITY_KERBEROS_ACCEPTOR_KEYTAB_FILEPATH = "plugins.security.kerberos.acceptor_keytab_filepath"; //no usage
    public static final String SECURITY_KERBEROS_ACCEPTOR_PRINCIPAL = "plugins.security.kerberos.acceptor_principal";//no usage
    public static final String SECURITY_CERT_OID = "plugins.security.cert.oid";// need to add default in Settings class
    public static final String SECURITY_CERT_INTERCLUSTER_REQUEST_EVALUATOR_CLASS = "plugins.security.cert.intercluster_request_evaluator_class";//no usage
    public static final String SECURITY_ADVANCED_MODULES_ENABLED = "plugins.security.advanced_modules_enabled";//problem
    public static final String SECURITY_NODES_DN = "plugins.security.nodes_dn";//default value same
    public static final String SECURITY_NODES_DN_DYNAMIC_CONFIG_ENABLED = "plugins.security.nodes_dn_dynamic_config_enabled";//default value same
    public static final String SECURITY_DISABLED = "plugins.security.disabled";//default value same
    public static final String SECURITY_CACHE_TTL_MINUTES = "plugins.security.cache.ttl_minutes";//default value same
    public static final String SECURITY_ALLOW_UNSAFE_DEMOCERTIFICATES = "plugins.security.allow_unsafe_democertificates";//default value same
    public static final String SECURITY_ALLOW_DEFAULT_INIT_SECURITYINDEX = "plugins.security.allow_default_init_securityindex";//default value same
    public static final String SECURITY_BACKGROUND_INIT_IF_SECURITYINDEX_NOT_EXIST = "plugins.security.background_init_if_securityindex_not_exist";//default value same

    public static final String SECURITY_ROLES_MAPPING_RESOLUTION = "plugins.security.roles_mapping_resolution";//default value in this file

    public static final String SECURITY_COMPLIANCE_HISTORY_WRITE_METADATA_ONLY = "plugins.security.compliance.history.write.metadata_only";//default value same
    public static final String SECURITY_COMPLIANCE_HISTORY_READ_METADATA_ONLY = "plugins.security.compliance.history.read.metadata_only";//default value same
    public static final String SECURITY_COMPLIANCE_HISTORY_READ_WATCHED_FIELDS = "plugins.security.compliance.history.read.watched_fields";//default value same
    public static final String SECURITY_COMPLIANCE_HISTORY_WRITE_WATCHED_INDICES = "plugins.security.compliance.history.write.watched_indices";//default value same
    public static final String SECURITY_COMPLIANCE_HISTORY_WRITE_LOG_DIFFS = "plugins.security.compliance.history.write.log_diffs";//default value same
    public static final String SECURITY_COMPLIANCE_HISTORY_READ_IGNORE_USERS = "plugins.security.compliance.history.read.ignore_users";//default value conflict // change settings default
    public static final String SECURITY_COMPLIANCE_HISTORY_WRITE_IGNORE_USERS = "plugins.security.compliance.history.write.ignore_users";//default value conflict // change settings default
    public static final String SECURITY_COMPLIANCE_HISTORY_EXTERNAL_CONFIG_ENABLED  = "plugins.security.compliance.history.external_config_enabled";//default value same, problem
    public static final String SECURITY_COMPLIANCE_DISABLE_ANONYMOUS_AUTHENTICATION  = "plugins.security.compliance.disable_anonymous_authentication";//default value same
    public static final String SECURITY_COMPLIANCE_IMMUTABLE_INDICES = "plugins.security.compliance.immutable_indices";//need to deal with default
    public static final String SECURITY_COMPLIANCE_SALT = "plugins.security.compliance.salt";//need to deal with default
    public static final String SECURITY_COMPLIANCE_SALT_DEFAULT = "e1ukloTsQlOgPquJ";//16 chars
    public static final String SECURITY_COMPLIANCE_HISTORY_INTERNAL_CONFIG_ENABLED  = "plugins.security.compliance.history.internal_config_enabled";//default value same, problem
    public static final String SECURITY_SSL_ONLY = "plugins.security.ssl_only";//default value same
    public static final String SECURITY_CONFIG_SSL_DUAL_MODE_ENABLED = "security_config.ssl_dual_mode_enabled";//default value same
    public static final String SECURITY_SSL_CERT_RELOAD_ENABLED = "plugins.security.ssl_cert_reload_enabled";//default value same
    public static final String SECURITY_DISABLE_ENVVAR_REPLACEMENT = "plugins.security.disable_envvar_replacement";//default value same

    public enum RolesMappingResolution {
        MAPPING_ONLY,
        BACKENDROLES_ONLY,
        BOTH
    }

    public static final String SECURITY_FILTER_SECURITYINDEX_FROM_ALL_REQUESTS = "plugins.security.filter_securityindex_from_all_requests";//default value same

    // REST API
    public static final String SECURITY_RESTAPI_ROLES_ENABLED = "plugins.security.restapi.roles_enabled";//no default problem
    public static final String SECURITY_RESTAPI_ENDPOINTS_DISABLED = "plugins.security.restapi.endpoints_disabled";//problem
    public static final String SECURITY_RESTAPI_PASSWORD_VALIDATION_REGEX = "plugins.security.restapi.password_validation_regex";// need to add default in Settings class null
    public static final String SECURITY_RESTAPI_PASSWORD_VALIDATION_ERROR_MESSAGE = "plugins.security.restapi.password_validation_error_message";//need to add default in Settings class "Password does not match minimum criteria"

    // Illegal Opcodes from here on
    public static final String SECURITY_UNSUPPORTED_DISABLE_REST_AUTH_INITIALLY = "plugins.security.unsupported.disable_rest_auth_initially";//default value same
    public static final String SECURITY_UNSUPPORTED_DISABLE_INTERTRANSPORT_AUTH_INITIALLY = "plugins.security.unsupported.disable_intertransport_auth_initially";//default value same
    public static final String SECURITY_UNSUPPORTED_RESTORE_SECURITYINDEX_ENABLED = "plugins.security.unsupported.restore.securityindex.enabled";//default value same
    public static final String SECURITY_UNSUPPORTED_INJECT_USER_ENABLED = "plugins.security.unsupported.inject_user.enabled";//default value same
    public static final String SECURITY_UNSUPPORTED_INJECT_ADMIN_USER_ENABLED = "plugins.security.unsupported.inject_user.admin.enabled";//default value same
    public static final String SECURITY_UNSUPPORTED_ALLOW_NOW_IN_DLS = "plugins.security.unsupported.allow_now_in_dls";//default value same

    public static final String SECURITY_UNSUPPORTED_RESTAPI_ALLOW_SECURITYCONFIG_MODIFICATION = "plugins.security.unsupported.restapi.allow_securityconfig_modification";//default value same
    public static final String SECURITY_UNSUPPORTED_LOAD_STATIC_RESOURCES = "plugins.security.unsupported.load_static_resources";//default value same
    public static final String SECURITY_UNSUPPORTED_ACCEPT_INVALID_CONFIG = "plugins.security.unsupported.accept_invalid_config";//default value same

    // Protected indices settings. Marked for deprecation, after all config indices move to System indices.
    public static final String SECURITY_PROTECTED_INDICES_ENABLED_KEY = "plugins.security.protected_indices.enabled";//default value same
    public static final Boolean SECURITY_PROTECTED_INDICES_ENABLED_DEFAULT = false;
    public static final String SECURITY_PROTECTED_INDICES_KEY = "plugins.security.protected_indices.indices";//default value same
    public static final List<String> SECURITY_PROTECTED_INDICES_DEFAULT = Collections.emptyList();
    public static final String SECURITY_PROTECTED_INDICES_ROLES_KEY = "plugins.security.protected_indices.roles";//default value same
    public static final List<String> SECURITY_PROTECTED_INDICES_ROLES_DEFAULT = Collections.emptyList();

    // Roles injection for plugins
    public static final String SECURITY_INJECTED_ROLES = "opendistro_security_injected_roles";

    // System indices settings
    public static final String SECURITY_SYSTEM_INDICES_ENABLED_KEY = "plugins.security.system_indices.enabled";//default value same
    public static final Boolean SECURITY_SYSTEM_INDICES_ENABLED_DEFAULT = false;
    public static final String SECURITY_SYSTEM_INDICES_KEY = "plugins.security.system_indices.indices";//default value same
    public static final List<String> SECURITY_SYSTEM_INDICES_DEFAULT = Collections.emptyList();

    public static Set<String> getSettingAsSet(final Settings settings, final String key, final List<String> defaultList, final boolean ignoreCaseForNone) {
        final List<String> list = settings.getAsList(key, defaultList);
        if (list.size() == 1 && "NONE".equals(ignoreCaseForNone? list.get(0).toUpperCase() : list.get(0))) {
            return Collections.emptySet();
        }
        return ImmutableSet.copyOf(list);
    }
}
