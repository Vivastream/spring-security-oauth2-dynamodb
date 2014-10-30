/**
 * Copyright 2014 Vivastream, LLC
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

package com.vivastream.security.oauth2.provider.token.store;

/**
 * Definition of the oauth_access_token and oauth_refresh_token table schemas, in an easily customizable fashion
 *
 * @author Zac Balson
 */
public class DynamoDBTokenSchema {

    private static final String DEFAULT_ACCESS_TABLE_NAME = "oauth_access_token";
    private static final String DEFAULT_ACCESS_COLUMN_TOKEN_ID = "token_id";
    private static final String DEFAULT_ACCESS_COLUMN_TOKEN = "token";
    private static final String DEFAULT_ACCESS_COLUMN_AUTHENTICATION_ID = "authentication_id";
    private static final String DEFAULT_ACCESS_COLUMN_USER_NAME = "user_name";
    private static final String DEFAULT_ACCESS_COLUMN_CLIENT_ID = "client_id";
    private static final String DEFAULT_ACCESS_COLUMN_AUTHENTICATION = "authentication";
    private static final String DEFAULT_ACCESS_COLUMN_REFRESH_TOKEN = "refresh_token";

    private static final String DEFAULT_ACCESS_INDEX_AUTHENTICATION_ID = "idx_authentication_id";
    private static final String DEFAULT_ACCESS_INDEX_REFRESH_TOKEN = "idx_refresh_token";

    private static final String DEFAULT_ACCESS_INDEX_CLIENT_ID_AND_USER_NAME = "idx_client_user";

    // For the GSI to allow for querying by Client/Client+User
    private static final String DEFAULT_ACCESS_COLUMN_IS_NULL_USER = "is_null_user";
    private static final String DEFAULT_IS_NULL_USER_TRUE_TOKEN = "1";
    private static final String DEFAULT_NULL_USER_TOKEN = "#";

    private static final String DEFAULT_REFRESH_TABLE_NAME = "oauth_refresh_token";
    private static final String DEFAULT_REFRESH_COLUMN_TOKEN_ID = "token_id";
    private static final String DEFAULT_REFRESH_COLUMN_TOKEN = "token";
    private static final String DEFAULT_REFRESH_COLUMN_AUTHENTICATION = "authentication";

    // Access Token Table
    private String accessTableName = DEFAULT_ACCESS_TABLE_NAME;

    // Access Token Table Columns
    private String accessColumnTokenId = DEFAULT_ACCESS_COLUMN_TOKEN_ID;
    private String accessColumnToken = DEFAULT_ACCESS_COLUMN_TOKEN;
    private String accessColumnAuthenticationId = DEFAULT_ACCESS_COLUMN_AUTHENTICATION_ID;
    private String accessColumnUserName = DEFAULT_ACCESS_COLUMN_USER_NAME;
    private String accessColumnClientId = DEFAULT_ACCESS_COLUMN_CLIENT_ID;
    private String accessColumnAuthentication = DEFAULT_ACCESS_COLUMN_AUTHENTICATION;
    private String accessColumnRefreshToken = DEFAULT_ACCESS_COLUMN_REFRESH_TOKEN;

    // Access Token Global Secondary Index [on accessColumnAuthenticationId]
    private String accessIndexAuthenticationId = DEFAULT_ACCESS_INDEX_AUTHENTICATION_ID;

    // Access Token Global Secondary Index [on accessColumnRefreshToken]
    private String accessIndexRefreshToken = DEFAULT_ACCESS_INDEX_REFRESH_TOKEN;

    // Access Token Global Secondary Index [on client id and user name]
    private String accessIndexClientIdAndUserName = DEFAULT_ACCESS_INDEX_CLIENT_ID_AND_USER_NAME;
    private String accessColumnIsNullUser = DEFAULT_ACCESS_COLUMN_IS_NULL_USER;
    private String accessIsNullUserTrueToken = DEFAULT_IS_NULL_USER_TRUE_TOKEN;
    private String accessNullUserToken = DEFAULT_NULL_USER_TOKEN;

    // Refresh Token Table
    private String refreshTableName = DEFAULT_REFRESH_TABLE_NAME;
    private String refreshColumnTokenId = DEFAULT_REFRESH_COLUMN_TOKEN_ID;
    private String refreshColumnToken = DEFAULT_REFRESH_COLUMN_TOKEN;
    private String refreshColumnAuthentication = DEFAULT_REFRESH_COLUMN_AUTHENTICATION;

    public String getAccessTableName() {
        return accessTableName;
    }

    public void setAccessTableName(String accessTableName) {
        this.accessTableName = accessTableName;
    }

    public String getAccessColumnTokenId() {
        return accessColumnTokenId;
    }

    public void setAccessColumnTokenId(String accessColumnTokenId) {
        this.accessColumnTokenId = accessColumnTokenId;
    }

    public String getAccessColumnToken() {
        return accessColumnToken;
    }

    public void setAccessColumnToken(String accessColumnToken) {
        this.accessColumnToken = accessColumnToken;
    }

    public String getAccessColumnAuthenticationId() {
        return accessColumnAuthenticationId;
    }

    public void setAccessColumnAuthenticationId(String accessColumnAuthenticationId) {
        this.accessColumnAuthenticationId = accessColumnAuthenticationId;
    }

    public String getAccessColumnUserName() {
        return accessColumnUserName;
    }

    public void setAccessColumnUserName(String accessColumnUserName) {
        this.accessColumnUserName = accessColumnUserName;
    }

    public String getAccessColumnClientId() {
        return accessColumnClientId;
    }

    public void setAccessColumnClientId(String accessColumnClientId) {
        this.accessColumnClientId = accessColumnClientId;
    }

    public String getAccessColumnAuthentication() {
        return accessColumnAuthentication;
    }

    public void setAccessColumnAuthentication(String accessColumnAuthentication) {
        this.accessColumnAuthentication = accessColumnAuthentication;
    }

    public String getAccessColumnRefreshToken() {
        return accessColumnRefreshToken;
    }

    public void setAccessColumnRefreshToken(String accessColumnRefreshToken) {
        this.accessColumnRefreshToken = accessColumnRefreshToken;
    }

    public String getAccessIndexAuthenticationId() {
        return accessIndexAuthenticationId;
    }

    public void setAccessIndexAuthenticationId(String accessIndexAuthenticationId) {
        this.accessIndexAuthenticationId = accessIndexAuthenticationId;
    }

    public String getAccessIndexRefreshToken() {
        return accessIndexRefreshToken;
    }

    public void setAccessIndexRefreshToken(String accessIndexRefreshToken) {
        this.accessIndexRefreshToken = accessIndexRefreshToken;
    }

    public String getAccessIndexClientIdAndUserName() {
        return accessIndexClientIdAndUserName;
    }

    public void setAccessIndexClientIdAndUserName(String accessIndexClientIdAndUserName) {
        this.accessIndexClientIdAndUserName = accessIndexClientIdAndUserName;
    }

    public String getAccessColumnIsNullUser() {
        return accessColumnIsNullUser;
    }

    public void setAccessColumnIsNullUser(String accessColumnIsNullUser) {
        this.accessColumnIsNullUser = accessColumnIsNullUser;
    }

    public String getAccessIsNullUserTrueToken() {
        return accessIsNullUserTrueToken;
    }

    public void setAccessIsNullUserTrueToken(String accessIsNullUserTrueToken) {
        this.accessIsNullUserTrueToken = accessIsNullUserTrueToken;
    }

    public String getAccessNullUserToken() {
        return accessNullUserToken;
    }

    public void setAccessNullUserToken(String accessNullUserToken) {
        this.accessNullUserToken = accessNullUserToken;
    }

    public String getRefreshTableName() {
        return refreshTableName;
    }

    public void setRefreshTableName(String refreshTableName) {
        this.refreshTableName = refreshTableName;
    }

    public String getRefreshColumnTokenId() {
        return refreshColumnTokenId;
    }

    public void setRefreshColumnTokenId(String refreshColumnTokenId) {
        this.refreshColumnTokenId = refreshColumnTokenId;
    }

    public String getRefreshColumnToken() {
        return refreshColumnToken;
    }

    public void setRefreshColumnToken(String refreshColumnToken) {
        this.refreshColumnToken = refreshColumnToken;
    }

    public String getRefreshColumnAuthentication() {
        return refreshColumnAuthentication;
    }

    public void setRefreshColumnAuthentication(String refreshColumnAuthentication) {
        this.refreshColumnAuthentication = refreshColumnAuthentication;
    }

}
