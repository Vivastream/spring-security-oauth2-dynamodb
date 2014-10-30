/**
 * Copyright 2014 Vivastream Inc.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */

package com.vivastream.security.oauth2.provider;

/**
 * Definition of the ClientDetails table schema, in an easily customizable fashion
 *
 * @author Zac Balson
 */
public class DynamoDBClientDetailsSchema {

    private static final String DEFAULT_TABLE_NAME = "client_details";

    private static final String DEFAULT_COLUMN_CLIENT_ID = "client_id";
    private static final String DEFAULT_COLUMN_CLIENT_SECRET = "client_secret";
    private static final String DEFAULT_COLUMN_RESOURCE_IDS = "resource_ids";
    private static final String DEFAULT_COLUMN_SCOPES = "scopes";
    private static final String DEFAULT_COLUMN_AUTHORIZED_GRANT_TYPES = "authorized_grant_types";
    private static final String DEFAULT_COLUMN_AUTHORITIES = "authorities";
    private static final String DEFAULT_COLUMN_REGISTERED_REDIRECT_URIS = "registered_redirect_uris";

    private String tableName = DEFAULT_TABLE_NAME;

    private String columnClientId = DEFAULT_COLUMN_CLIENT_ID;
    private String columnClientSecret = DEFAULT_COLUMN_CLIENT_SECRET;
    private String columnResourceIds = DEFAULT_COLUMN_RESOURCE_IDS;
    private String columnScopes = DEFAULT_COLUMN_SCOPES;
    private String columnAuthorizedGrantTypes = DEFAULT_COLUMN_AUTHORIZED_GRANT_TYPES;
    private String columnAuthorities = DEFAULT_COLUMN_AUTHORITIES;
    private String columnRegisteredRedirectUris = DEFAULT_COLUMN_REGISTERED_REDIRECT_URIS;

    public String getTableName() {
        return tableName;
    }

    public void setTableName(String tableName) {
        this.tableName = tableName;
    }

    public String getColumnClientId() {
        return columnClientId;
    }

    public void setColumnClientId(String columnClientId) {
        this.columnClientId = columnClientId;
    }

    public String getColumnClientSecret() {
        return columnClientSecret;
    }

    public void setColumnClientSecret(String columnClientSecret) {
        this.columnClientSecret = columnClientSecret;
    }

    public String getColumnResourceIds() {
        return columnResourceIds;
    }

    public void setColumnResourceIds(String columnResourceIds) {
        this.columnResourceIds = columnResourceIds;
    }

    public String getColumnScopes() {
        return columnScopes;
    }

    public void setColumnScopes(String columnScopes) {
        this.columnScopes = columnScopes;
    }

    public String getColumnAuthorizedGrantTypes() {
        return columnAuthorizedGrantTypes;
    }

    public void setColumnAuthorizedGrantTypes(String columnAuthorizedGrantTypes) {
        this.columnAuthorizedGrantTypes = columnAuthorizedGrantTypes;
    }

    public String getColumnAuthorities() {
        return columnAuthorities;
    }

    public void setColumnAuthorities(String columnAuthorities) {
        this.columnAuthorities = columnAuthorities;
    }

    public String getColumnRegisteredRedirectUris() {
        return columnRegisteredRedirectUris;
    }

    public void setColumnRegisteredRedirectUris(String columnRegisteredRedirectUris) {
        this.columnRegisteredRedirectUris = columnRegisteredRedirectUris;
    }

}
