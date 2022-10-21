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

package com.vivastream.security.oauth2.provider.token.store;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.AuthenticationKeyGenerator;
import org.springframework.security.oauth2.provider.token.DefaultAuthenticationKeyGenerator;
import org.springframework.security.oauth2.provider.token.TokenStore;

import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.amazonaws.services.dynamodbv2.model.AttributeAction;
import com.amazonaws.services.dynamodbv2.model.AttributeValue;
import com.amazonaws.services.dynamodbv2.model.AttributeValueUpdate;
import com.amazonaws.services.dynamodbv2.model.ComparisonOperator;
import com.amazonaws.services.dynamodbv2.model.Condition;
import com.amazonaws.services.dynamodbv2.model.KeysAndAttributes;
import com.vivastream.dynamodb.core.DynamoDBTemplate;
import com.vivastream.dynamodb.core.ObjectExtractor;
import com.vivastream.dynamodb.exception.EmptyResultDataAccessException;
import com.vivastream.dynamodb.exception.IncorrectResultSizeDataAccessException;
import com.vivastream.security.oauth2.common.util.ByteBufferUtils;
import com.vivastream.security.oauth2.common.util.DynamoDBUtils;

/**
 * Implementation of token services that stores tokens in DynamoDB.  This was primarily based off of the
 * functionality of the JdbcTokenStore.
 *
 * @author Zac Balson
 */
public class DynamoDBTokenStore implements TokenStore {

    private final Log LOG = LogFactory.getLog(getClass());

    private AuthenticationKeyGenerator authenticationKeyGenerator = new DefaultAuthenticationKeyGenerator();

    private final DynamoDBTemplate dynamoDBTemplate;
    private final DynamoDBTokenSchema schema;

    public DynamoDBTokenStore(AmazonDynamoDB client) {
        this(client, new DynamoDBTokenSchema());
    }

    public DynamoDBTemplate getDynamoDBTemplate() {
        return dynamoDBTemplate;
    }

    public DynamoDBTokenStore(AmazonDynamoDB client, DynamoDBTokenSchema schema) {
        this.dynamoDBTemplate = new DynamoDBTemplate(client);
        this.schema = schema;
    }

    public void setAuthenticationKeyGenerator(AuthenticationKeyGenerator authenticationKeyGenerator) {
        this.authenticationKeyGenerator = authenticationKeyGenerator;
    }

    public OAuth2AccessToken getAccessToken(OAuth2Authentication authentication) {
        OAuth2AccessToken accessToken = null;

        String key = authenticationKeyGenerator.extractKey(authentication);
        try {
            String accessTokenId = getDynamoDBTemplate().queryUnique(schema.getAccessTableName(), schema.getAccessIndexAuthenticationId(), // 
                    Collections.singletonMap(schema.getAccessColumnAuthenticationId(), new Condition().withComparisonOperator(ComparisonOperator.EQ).withAttributeValueList(new AttributeValue(key))), // 
                    new ObjectExtractor<String>() {

                        public String extract(Map<String, AttributeValue> values) {
                            return values.get(schema.getAccessColumnTokenId()).getS();
                        }
                    });
            accessToken = getDynamoDBTemplate().get(schema.getAccessTableName(), Collections.singletonMap(schema.getAccessColumnTokenId(), new AttributeValue(accessTokenId)), new ObjectExtractor<OAuth2AccessToken>() {

                public OAuth2AccessToken extract(Map<String, AttributeValue> values) {
                    return deserializeAccessToken(values.get(schema.getAccessColumnToken()).getB());
                }
            });
        } catch (EmptyResultDataAccessException | IncorrectResultSizeDataAccessException e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Failed to find access token for authentication " + authentication);
            }
        } catch (IllegalArgumentException e) {
            LOG.error("Could not extract access token for authentication " + authentication, e);
        }

        if (accessToken != null && !key.equals(authenticationKeyGenerator.extractKey(readAuthentication(accessToken.getValue())))) {
            // Keep the store consistent (maybe the same user is represented by this authentication but the details have
            // changed)
            storeAccessToken(accessToken, authentication);
        }
        return accessToken;
    }

    public void storeAccessToken(OAuth2AccessToken token, OAuth2Authentication authentication) {
        String refreshToken = null;
        if (token.getRefreshToken() != null) {
            refreshToken = token.getRefreshToken().getValue();
        }

        // the JdbcTokenStore removes the existing token for this token_id [if it exists]
        // We'll avoid doing so for now, unless a compelling reason to do otherwise presents itself
        //        if (readAccessToken(token.getValue()) != null) {
        //            removeAccessToken(token.getValue());
        //        }

        Map<String, AttributeValueUpdate> updates = new HashMap<String, AttributeValueUpdate>();
        updates.put(schema.getAccessColumnToken(), new AttributeValueUpdate(new AttributeValue().withB(serializeAccessToken(token)), AttributeAction.PUT));
        DynamoDBUtils.nullSafeUpdateS(updates, schema.getAccessColumnAuthenticationId(), authenticationKeyGenerator.extractKey(authentication));
        if (authentication.isClientOnly() || authentication.getName() == null || authentication.getName().length() == 0) {
            DynamoDBUtils.nullSafeUpdateS(updates, schema.getAccessColumnUserName(), schema.getAccessNullUserToken());
            updates.put(schema.getAccessColumnIsNullUser(), new AttributeValueUpdate(new AttributeValue().withN(schema.getAccessIsNullUserTrueToken()), AttributeAction.PUT));
        } else {
            DynamoDBUtils.nullSafeUpdateS(updates, schema.getAccessColumnUserName(), authentication.getName());
            DynamoDBUtils.nullSafeUpdateS(updates, schema.getAccessColumnIsNullUser(), null);
        }

        DynamoDBUtils.nullSafeUpdateS(updates, schema.getAccessColumnClientId(), authentication.getOAuth2Request().getClientId());
        updates.put(schema.getAccessColumnAuthentication(), new AttributeValueUpdate(new AttributeValue().withB(serializeAuthentication(authentication)), AttributeAction.PUT));
        DynamoDBUtils.nullSafeUpdateS(updates, schema.getAccessColumnRefreshToken(), extractTokenKey(refreshToken));

        getDynamoDBTemplate().update(schema.getAccessTableName(), // 
                Collections.singletonMap(schema.getAccessColumnTokenId(), new AttributeValue(extractTokenKey(token.getValue()))), // 
                updates);
    }

    public OAuth2AccessToken readAccessToken(String tokenValue) {
        OAuth2AccessToken accessToken = null;

        try {
            accessToken = getDynamoDBTemplate().get(schema.getAccessTableName(), Collections.singletonMap(schema.getAccessColumnTokenId(), new AttributeValue(extractTokenKey(tokenValue))), new ObjectExtractor<OAuth2AccessToken>() {

                public OAuth2AccessToken extract(Map<String, AttributeValue> values) {
                    return deserializeAccessToken(values.get(schema.getAccessColumnToken()).getB());
                }
            }, schema.getAccessColumnToken());
        } catch (EmptyResultDataAccessException e) {
            if (LOG.isInfoEnabled()) {
                LOG.info("Failed to find access token for token " + tokenValue);
            }
        } catch (IllegalArgumentException e) {
            LOG.warn("Failed to deserialize access token for " + tokenValue, e);
            removeAccessToken(tokenValue);
        }

        return accessToken;
    }

    public void removeAccessToken(OAuth2AccessToken token) {
        removeAccessToken(token.getValue());
    }

    public void removeAccessToken(String tokenValue) {
        getDynamoDBTemplate().delete(schema.getAccessTableName(), Collections.singletonMap(schema.getAccessColumnTokenId(), new AttributeValue(extractTokenKey(tokenValue))));
    }

    public OAuth2Authentication readAuthentication(OAuth2AccessToken token) {
        return readAuthentication(token.getValue());
    }

    public OAuth2Authentication readAuthentication(String token) {
        OAuth2Authentication authentication = null;

        try {
            authentication = getDynamoDBTemplate().get(schema.getAccessTableName(), Collections.singletonMap(schema.getAccessColumnTokenId(), new AttributeValue(extractTokenKey(token))), new ObjectExtractor<OAuth2Authentication>() {

                public OAuth2Authentication extract(Map<String, AttributeValue> values) {
                    return deserializeAuthentication(values.get(schema.getAccessColumnAuthentication()).getB());
                }
            }, schema.getAccessColumnAuthentication());
        } catch (EmptyResultDataAccessException e) {
            if (LOG.isInfoEnabled()) {
                LOG.info("Failed to find access token for token " + token);
            }
        } catch (IllegalArgumentException e) {
            LOG.warn("Failed to deserialize authentication for " + token, e);
            removeAccessToken(token);
        }

        return authentication;
    }

    public void storeRefreshToken(OAuth2RefreshToken refreshToken, OAuth2Authentication authentication) {
        Map<String, AttributeValueUpdate> updates = new HashMap<String, AttributeValueUpdate>();
        updates.put(schema.getRefreshColumnToken(), new AttributeValueUpdate(new AttributeValue().withB(serializeRefreshToken(refreshToken)), AttributeAction.PUT));
        updates.put(schema.getRefreshColumnAuthentication(), new AttributeValueUpdate(new AttributeValue().withB(serializeAuthentication(authentication)), AttributeAction.PUT));

        getDynamoDBTemplate().update(schema.getRefreshTableName(), // 
                Collections.singletonMap(schema.getRefreshColumnTokenId(), new AttributeValue(extractTokenKey(refreshToken.getValue()))), // 
                updates);
    }

    public OAuth2RefreshToken readRefreshToken(String token) {
        OAuth2RefreshToken refreshToken = null;

        try {
            refreshToken = getDynamoDBTemplate().get(schema.getRefreshTableName(), Collections.singletonMap(schema.getRefreshColumnTokenId(), new AttributeValue(extractTokenKey(token))), new ObjectExtractor<OAuth2RefreshToken>() {

                public OAuth2RefreshToken extract(Map<String, AttributeValue> values) {
                    return deserializeRefreshToken(values.get(schema.getRefreshColumnToken()).getB());
                }
            }, schema.getRefreshColumnToken());
        } catch (EmptyResultDataAccessException e) {
            if (LOG.isInfoEnabled()) {
                LOG.info("Failed to find refresh token for token " + token);
            }
        } catch (IllegalArgumentException e) {
            LOG.warn("Failed to deserialize refresh token for token " + token, e);
            removeRefreshToken(token);
        }

        return refreshToken;
    }

    public void removeRefreshToken(OAuth2RefreshToken token) {
        removeRefreshToken(token.getValue());
    }

    public void removeRefreshToken(String token) {
        getDynamoDBTemplate().delete(schema.getRefreshTableName(), Collections.singletonMap(schema.getRefreshColumnTokenId(), new AttributeValue(extractTokenKey(token))));
    }

    public OAuth2Authentication readAuthenticationForRefreshToken(OAuth2RefreshToken token) {
        return readAuthenticationForRefreshToken(token.getValue());
    }

    public OAuth2Authentication readAuthenticationForRefreshToken(String value) {
        OAuth2Authentication authentication = null;

        try {
            authentication = getDynamoDBTemplate().get(schema.getRefreshTableName(), Collections.singletonMap(schema.getRefreshColumnTokenId(), new AttributeValue(extractTokenKey(value))), new ObjectExtractor<OAuth2Authentication>() {

                public OAuth2Authentication extract(Map<String, AttributeValue> values) {
                    return deserializeAuthentication(values.get(schema.getRefreshColumnAuthentication()).getB());
                }
            }, schema.getRefreshColumnAuthentication());
        } catch (EmptyResultDataAccessException e) {
            if (LOG.isInfoEnabled()) {
                LOG.info("Failed to find refresh token for token " + value);
            }
        } catch (IllegalArgumentException e) {
            LOG.warn("Failed to deserialize authentication for " + value, e);
            removeRefreshToken(value);
        }

        return authentication;
    }

    public void removeAccessTokenUsingRefreshToken(OAuth2RefreshToken refreshToken) {
        removeAccessTokenUsingRefreshToken(refreshToken.getValue());
    }

    public void removeAccessTokenUsingRefreshToken(String refreshToken) {
        String tokenId = null;

        try {
            tokenId = getDynamoDBTemplate().queryUnique(schema.getAccessTableName(), schema.getAccessIndexRefreshToken(), //
                    Collections.singletonMap(schema.getAccessColumnRefreshToken(), new Condition().withAttributeValueList(new AttributeValue(extractTokenKey(refreshToken))).withComparisonOperator(ComparisonOperator.EQ)), // 
                    new ObjectExtractor<String>() {

                        public String extract(Map<String, AttributeValue> values) {
                            return values.get(schema.getAccessColumnTokenId()).getS();
                        }
                    }, schema.getAccessColumnTokenId());
        } catch (EmptyResultDataAccessException | IncorrectResultSizeDataAccessException e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Failed to find access token for refresh token " + refreshToken);
            }
        }

        if (tokenId == null) {
            return;
        }

        getDynamoDBTemplate().delete(schema.getAccessTableName(), Collections.singletonMap(schema.getAccessColumnTokenId(), new AttributeValue(tokenId)));
    }

    public Collection<OAuth2AccessToken> findTokensByClientId(String clientId) {
        return loadTokensByClientAndUserIndex(Collections.singletonMap(schema.getAccessColumnClientId(), new Condition().withAttributeValueList(new AttributeValue(clientId)).withComparisonOperator(ComparisonOperator.EQ)), false);
    }

    private Collection<OAuth2AccessToken> loadTokensByClientAndUserIndex(Map<String, Condition> keyCondition, boolean filterOutNullUsers) {
        List<OAuth2AccessToken> accessTokens = new ArrayList<OAuth2AccessToken>();

        List<String> accessTokenIds = null;
        try {
            accessTokenIds = getDynamoDBTemplate().query(schema.getAccessTableName(), schema.getAccessIndexClientIdAndUserName(), keyCondition, //
                    new ObjectExtractor<String>() {

                        public String extract(Map<String, AttributeValue> values) {
                            return values.get(schema.getAccessColumnTokenId()).getS();
                        }
                    }, schema.getAccessColumnTokenId());

            List<Map<String, AttributeValue>> keys = new ArrayList<Map<String, AttributeValue>>(accessTokenIds.size());
            for (String accessTokenId : accessTokenIds) {
                keys.add(Collections.singletonMap(schema.getAccessColumnTokenId(), new AttributeValue(accessTokenId)));
            }
            if (filterOutNullUsers) {
                accessTokens = getDynamoDBTemplate().batchGet(schema.getAccessTableName(), // 
                        new KeysAndAttributes().withKeys(keys).withConsistentRead(true).withAttributesToGet(schema.getAccessColumnTokenId(), schema.getAccessColumnToken(), schema.getAccessColumnIsNullUser()), // 
                        new NonNullUserSafeAccessTokenExtractor());
            } else {
                accessTokens = getDynamoDBTemplate().batchGet(schema.getAccessTableName(), // 
                        new KeysAndAttributes().withKeys(keys).withConsistentRead(true).withAttributesToGet(schema.getAccessColumnTokenId(), schema.getAccessColumnToken()), // 
                        new SafeAccessTokenExtractor());
            }
        } catch (EmptyResultDataAccessException e) {
            if (LOG.isInfoEnabled()) {
                LOG.info("Failed to find access token for " + keyCondition.toString());
            }
        }
        accessTokens = removeNulls(accessTokens);

        return accessTokens;
    }

    public Collection<OAuth2AccessToken> findTokensByClientIdAndUserName(String clientId, String userName) {
        // If we are asked to load tokens for a userName that matches our null user placeholder, we need to do a little additional filtering
        boolean filterOutNullUser = schema.getAccessNullUserToken().equals(userName);

        Map<String, Condition> keyConditions = new HashMap<String, Condition>(4);
        keyConditions.put(schema.getAccessColumnClientId(), new Condition().withComparisonOperator(ComparisonOperator.EQ).withAttributeValueList(new AttributeValue(clientId)));
        keyConditions.put(schema.getAccessColumnUserName(), new Condition().withComparisonOperator(ComparisonOperator.EQ).withAttributeValueList(new AttributeValue(userName)));
        return loadTokensByClientAndUserIndex(keyConditions, filterOutNullUser);
    }

    private List<OAuth2AccessToken> removeNulls(List<OAuth2AccessToken> accessTokens) {
        List<OAuth2AccessToken> tokens = new ArrayList<OAuth2AccessToken>();
        for (OAuth2AccessToken token : accessTokens) {
            if (token != null) {
                tokens.add(token);
            }
        }
        return tokens;
    }

    protected String extractTokenKey(String value) {
        if (value == null) {
            return null;
        }
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("MD5");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("MD5 algorithm not available.  Fatal (should be in the JDK).");
        }

        try {
            byte[] bytes = digest.digest(value.getBytes("UTF-8"));
            return String.format("%032x", new BigInteger(1, bytes));
        } catch (UnsupportedEncodingException e) {
            throw new IllegalStateException("UTF-8 encoding not available.  Fatal (should be in the JDK).");
        }
    }

    private class SafeAccessTokenExtractor implements ObjectExtractor<OAuth2AccessToken> {

        @Override
        public OAuth2AccessToken extract(Map<String, AttributeValue> values) {
            try {
                return deserializeAccessToken(values.get(schema.getAccessColumnToken()).getB());
            } catch (IllegalArgumentException e) {
                String tokenId = values.get(schema.getAccessColumnTokenId()).getS();
                getDynamoDBTemplate().delete(schema.getAccessTableName(), Collections.singletonMap(schema.getAccessColumnTokenId(), new AttributeValue(tokenId)));
                return null;
            }
        }
    }

    private class NonNullUserSafeAccessTokenExtractor extends SafeAccessTokenExtractor {

        @Override
        public OAuth2AccessToken extract(Map<String, AttributeValue> values) {
            AttributeValue isNullUserAttribute = values.get(schema.getAccessColumnIsNullUser());
            if (isNullUserAttribute != null && schema.getAccessIsNullUserTrueToken().equals(isNullUserAttribute.getN())) {
                return null;
            }
            return super.extract(values);
        }
    }

    protected ByteBuffer serializeAccessToken(OAuth2AccessToken token) {
        return ByteBufferUtils.serialize(token);
    }

    protected ByteBuffer serializeRefreshToken(OAuth2RefreshToken token) {
        return ByteBufferUtils.serialize(token);
    }

    protected ByteBuffer serializeAuthentication(OAuth2Authentication authentication) {
        return ByteBufferUtils.serialize(authentication);
    }

    protected OAuth2AccessToken deserializeAccessToken(ByteBuffer token) {
        return ByteBufferUtils.deserialize(token);
    }

    protected OAuth2RefreshToken deserializeRefreshToken(ByteBuffer token) {
        return ByteBufferUtils.deserialize(token);
    }

    protected OAuth2Authentication deserializeAuthentication(ByteBuffer authentication) {
        return ByteBufferUtils.deserialize(authentication);
    }

}
