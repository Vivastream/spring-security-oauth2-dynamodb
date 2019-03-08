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

import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.util.StringUtils;

import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.amazonaws.services.dynamodbv2.model.AttributeValue;
import com.amazonaws.services.dynamodbv2.model.AttributeValueUpdate;
import com.amazonaws.services.dynamodbv2.model.GetItemRequest;
import com.amazonaws.services.dynamodbv2.model.GetItemResult;
import com.vivastream.security.oauth2.common.util.DynamoDBUtils;

/**
 * Service for saving/loading UserDetails from DynamoDB
 *
 * @author Zac Balson
 */
public class DynamoDBUserDetailsManager implements UserDetailsManager {

    protected final Log logger = LogFactory.getLog(getClass());

    protected final AmazonDynamoDB client;
    protected final DynamoDBUserDetailsSchema schema;

    protected AuthenticationManager authenticationManager;

    public DynamoDBUserDetailsManager(AmazonDynamoDB client) {
        this(client, new DynamoDBUserDetailsSchema());
    }

    public DynamoDBUserDetailsManager(AmazonDynamoDB client, DynamoDBUserDetailsSchema schema) {
        this.client = client;
        this.schema = schema;
    }

    public void setAuthenticationManager(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return loadUserByUsername(username, false);
    }

    protected UserDetails loadUserByUsername(String username, boolean consistentRead) throws UsernameNotFoundException {
        GetItemResult result = client.getItem(schema.getTableName(), Collections.singletonMap(schema.getColumnUsername(), new AttributeValue(username)), consistentRead);

        UserDetails user = buildUserFromItem(result.getItem());

        if (user == null) {
            throw new UsernameNotFoundException("No user found for " + username);
        }
        return user;
    }

    protected UserDetails buildUserFromItem(Map<String, AttributeValue> item) {
        if (item == null) {
            return null;
        }
        String username = DynamoDBUtils.nullSafeGetS(item.get(schema.getColumnUsername()));
        String password = DynamoDBUtils.nullSafeGetS(item.get(schema.getColumnPassword()));
        String authoritiesStr = DynamoDBUtils.nullSafeGetS(item.get(schema.getColumnAuthorities()));

        List<GrantedAuthority> authorities = null;
        if (StringUtils.hasText(authoritiesStr)) {
            authorities = AuthorityUtils.commaSeparatedStringToAuthorityList(authoritiesStr);
        } else {
            authorities = Collections.emptyList();
        }

        return buildUserFromItem(username, password, authorities, item);
    }

    protected UserDetails buildUserFromItem(String username, String password, Collection<? extends GrantedAuthority> authorities, Map<String, AttributeValue> item) {
        return new User(username, password, authorities);
    }

    @Override
    public void createUser(UserDetails newUser) {
        // Make sure it doesn't already exist
        if (userExists(newUser.getUsername())) {
            throw new UserDetailsAlreadyExistsException("User already exists: " + newUser.getUsername());
        }
        updateUser(newUser);
    }

    @Override
    public void updateUser(UserDetails user) {
        Map<String, AttributeValueUpdate> updates = new HashMap<String, AttributeValueUpdate>();
        DynamoDBUtils.nullSafeUpdateS(updates, schema.getColumnPassword(), user.getPassword());
        DynamoDBUtils.nullSafeUpdateS(updates, schema.getColumnAuthorities(), StringUtils.collectionToCommaDelimitedString(AuthorityUtils.authorityListToSet(user.getAuthorities())));
        enrichUpdates(updates, user);
        client.updateItem(schema.getTableName(), Collections.singletonMap(schema.getColumnUsername(), new AttributeValue(user.getUsername())), updates);
    }

    // A hook where additional fields from the user object can be added to the update list
    protected void enrichUpdates(Map<String, AttributeValueUpdate> updates, UserDetails user) {
    }

    @Override
    public void deleteUser(String username) {
        client.deleteItem(schema.getTableName(), Collections.singletonMap(schema.getColumnUsername(), new AttributeValue(username)));
    }

    @Override
    public void changePassword(String oldPassword, String newPassword) {
        Authentication currentUserAuth = SecurityContextHolder.getContext().getAuthentication();

        if (currentUserAuth == null) {
            // This would indicate bad coding somewhere
            throw new AccessDeniedException("Can't change password as no Authentication object found in context " + "for current user.");
        }

        String username = currentUserAuth.getName();
        UserDetails user = loadUserByUsername(username, true);

        logger.debug("Changing password for user '" + username + "'");

        // If an authentication manager has been set, re-authenticate the user with the supplied password.
        if (authenticationManager != null) {
            logger.debug("Reauthenticating user '" + username + "' for password change request.");

            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, oldPassword));
        } else {
            logger.debug("No authentication manager set. Password won't be re-checked.");
        }

        Map<String, AttributeValueUpdate> updates = new HashMap<String, AttributeValueUpdate>();
        DynamoDBUtils.nullSafeUpdateS(updates, schema.getColumnPassword(), user.getPassword());
        client.updateItem(schema.getTableName(), Collections.singletonMap(schema.getColumnUsername(), new AttributeValue(username)), updates);

        SecurityContextHolder.getContext().setAuthentication(createNewAuthentication(user, currentUserAuth, newPassword));
    }

    protected Authentication createNewAuthentication(UserDetails user, Authentication currentAuth, String newPassword) {

        UsernamePasswordAuthenticationToken newAuthentication = new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities());
        newAuthentication.setDetails(currentAuth.getDetails());

        return newAuthentication;
    }

    @Override
    public boolean userExists(String username) {
        GetItemRequest request = new GetItemRequest(schema.getTableName(), Collections.singletonMap(schema.getColumnUsername(), new AttributeValue(username))) //
                .withAttributesToGet(schema.getColumnUsername());
        GetItemResult result = client.getItem(request);
        return result.getItem() != null;
    }

}
