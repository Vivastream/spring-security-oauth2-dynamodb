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
 * Definition of the UserDetails table schema, in an easily customizable fashion
 *
 * @author Zac Balson
 */
public class DynamoDBUserDetailsSchema {

    private static final String DEFAULT_TABLE_NAME = "user_details";

    private static final String DEFAULT_COLUMN_USERNAME = "username";
    private static final String DEFAULT_COLUMN_PASSWORD = "password";
    private static final String DEFAULT_COLUMN_AUTHORITIES = "authorities";

    private String tableName = DEFAULT_TABLE_NAME;

    private String columnUsername = DEFAULT_COLUMN_USERNAME;
    private String columnPassword = DEFAULT_COLUMN_PASSWORD;
    private String columnAuthorities = DEFAULT_COLUMN_AUTHORITIES;

    public String getTableName() {
        return tableName;
    }

    public void setTableName(String tableName) {
        this.tableName = tableName;
    }

    public String getColumnUsername() {
        return columnUsername;
    }

    public void setColumnUsername(String columnUsername) {
        this.columnUsername = columnUsername;
    }

    public String getColumnPassword() {
        return columnPassword;
    }

    public void setColumnPassword(String columnPassword) {
        this.columnPassword = columnPassword;
    }

    public String getColumnAuthorities() {
        return columnAuthorities;
    }

    public void setColumnAuthorities(String columnAuthorities) {
        this.columnAuthorities = columnAuthorities;
    }

}
