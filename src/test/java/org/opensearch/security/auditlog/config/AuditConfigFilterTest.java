/*
 * Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License").
 *  You may not use this file except in compliance with the License.
 *  A copy of the License is located at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  or in the "license" file accompanying this file. This file is distributed
 *  on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 *  express or implied. See the License for the specific language governing
 *  permissions and limitations under the License.
 */

package org.opensearch.security.auditlog.config;

import org.opensearch.security.auditlog.impl.AuditCategory;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.support.WildcardMatcher;
import org.junit.Assert;
import org.opensearch.common.settings.Settings;
import org.junit.Test;

import java.util.Collections;
import java.util.EnumSet;

import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertEquals;

public class AuditConfigFilterTest {

    @Test
    public void testDefault() {
        // arrange
        final WildcardMatcher defaultIgnoredUserMatcher = WildcardMatcher.from("kibanaserver");
        final EnumSet<AuditCategory> defaultDisabledCategories = EnumSet.of(AuditCategory.AUTHENTICATED, AuditCategory.GRANTED_PRIVILEGES);
        // act
        final AuditConfig.Filter auditConfigFilter = AuditConfig.Filter.from(Settings.EMPTY);
        // assert
        assertTrue(auditConfigFilter.isRestApiAuditEnabled());
        assertTrue(auditConfigFilter.isTransportApiAuditEnabled());
        assertTrue(auditConfigFilter.shouldLogRequestBody());
        assertTrue(auditConfigFilter.shouldResolveIndices());
        assertFalse(auditConfigFilter.shouldResolveBulkRequests());
        assertTrue(auditConfigFilter.shouldExcludeSensitiveHeaders());
        assertSame(WildcardMatcher.NONE, auditConfigFilter.getIgnoredAuditRequestsMatcher());
        Assert.assertEquals(defaultIgnoredUserMatcher, auditConfigFilter.getIgnoredAuditUsersMatcher());
        assertEquals(auditConfigFilter.getDisabledRestCategories(), defaultDisabledCategories);
        assertEquals(auditConfigFilter.getDisabledTransportCategories(), defaultDisabledCategories);
    }

    @Test
    public void testConfig() {
        // arrange
        final Settings settings = Settings.builder()
                .put(ConfigConstants.SECURITY_AUDIT_ENABLE_REST, false)
                .put(ConfigConstants.SECURITY_AUDIT_ENABLE_TRANSPORT, false)
                .put(ConfigConstants.SECURITY_AUDIT_RESOLVE_BULK_REQUESTS, true)
                .put(ConfigConstants.SECURITY_AUDIT_LOG_REQUEST_BODY, false)
                .put(ConfigConstants.SECURITY_AUDIT_RESOLVE_INDICES, false)
                .put(ConfigConstants.SECURITY_AUDIT_EXCLUDE_SENSITIVE_HEADERS, false)
                .putList(ConfigConstants.SECURITY_AUDIT_IGNORE_REQUESTS, "test-request")
                .putList(ConfigConstants.SECURITY_AUDIT_IGNORE_USERS, "test-user")
                .putList(ConfigConstants.SECURITY_AUDIT_CONFIG_DISABLED_REST_CATEGORIES,
                        AuditCategory.BAD_HEADERS.toString(), AuditCategory.SSL_EXCEPTION.toString())
                .putList(ConfigConstants.SECURITY_AUDIT_CONFIG_DISABLED_TRANSPORT_CATEGORIES,
                        AuditCategory.FAILED_LOGIN.toString(), AuditCategory.MISSING_PRIVILEGES.toString())
                .build();
        // act
        final AuditConfig.Filter auditConfigFilter = AuditConfig.Filter.from(settings);
        // assert
        assertFalse(auditConfigFilter.isRestApiAuditEnabled());
        assertFalse(auditConfigFilter.isTransportApiAuditEnabled());
        assertFalse(auditConfigFilter.shouldLogRequestBody());
        assertFalse(auditConfigFilter.shouldResolveIndices());
        assertTrue(auditConfigFilter.shouldResolveBulkRequests());
        assertFalse(auditConfigFilter.shouldExcludeSensitiveHeaders());
        Assert.assertEquals(WildcardMatcher.from(Collections.singleton("test-user")), auditConfigFilter.getIgnoredAuditUsersMatcher());
        Assert.assertEquals(WildcardMatcher.from(Collections.singleton("test-request")), auditConfigFilter.getIgnoredAuditRequestsMatcher());
        assertEquals(auditConfigFilter.getDisabledRestCategories(), EnumSet.of(AuditCategory.BAD_HEADERS, AuditCategory.SSL_EXCEPTION));
        assertEquals(auditConfigFilter.getDisabledTransportCategories(), EnumSet.of(AuditCategory.FAILED_LOGIN, AuditCategory.MISSING_PRIVILEGES));
    }

    @Test
    public void testNone() {
        // arrange
        final Settings settings = Settings.builder()
                .putList(ConfigConstants.SECURITY_AUDIT_IGNORE_USERS, "NONE")
                .putList(ConfigConstants.SECURITY_AUDIT_CONFIG_DISABLED_REST_CATEGORIES,
                        "None")
                .putList(ConfigConstants.SECURITY_AUDIT_CONFIG_DISABLED_TRANSPORT_CATEGORIES,
                        "none")
                .build();
        // act
        final AuditConfig.Filter auditConfigFilter = AuditConfig.Filter.from(settings);
        // assert
        assertSame(WildcardMatcher.NONE, auditConfigFilter.getIgnoredAuditUsersMatcher());
        assertTrue(auditConfigFilter.getDisabledRestCategories().isEmpty());
        assertTrue(auditConfigFilter.getDisabledTransportCategories().isEmpty());
    }

    @Test
    public void testEmpty() {
        // arrange
        final Settings settings = Settings.builder()
                .putList(ConfigConstants.SECURITY_AUDIT_IGNORE_USERS, Collections.emptyList())
                .putList(ConfigConstants.SECURITY_AUDIT_IGNORE_REQUESTS,  Collections.emptyList())
                .putList(ConfigConstants.SECURITY_AUDIT_CONFIG_DISABLED_REST_CATEGORIES,
                        Collections.emptyList())
                .putList(ConfigConstants.SECURITY_AUDIT_CONFIG_DISABLED_TRANSPORT_CATEGORIES,
                        Collections.emptyList())
                .build();
        // act
        final AuditConfig.Filter auditConfigFilter = AuditConfig.Filter.from(settings);
        // assert
        assertSame(WildcardMatcher.NONE, auditConfigFilter.getIgnoredAuditUsersMatcher());
        assertTrue(auditConfigFilter.getDisabledRestCategories().isEmpty());
        assertTrue(auditConfigFilter.getDisabledTransportCategories().isEmpty());
    }
}
