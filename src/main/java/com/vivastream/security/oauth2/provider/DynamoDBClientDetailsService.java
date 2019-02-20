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

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.ClientRegistrationException;
import org.springframework.security.oauth2.provider.NoSuchClientException;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.util.StringUtils;

import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.amazonaws.services.dynamodbv2.model.AttributeValue;
import com.amazonaws.services.dynamodbv2.model.AttributeValueUpdate;
import com.amazonaws.services.dynamodbv2.model.GetItemResult;
import com.vivastream.security.oauth2.common.util.DynamoDBUtils;

/**
 * Service for saving/loading ClientDetails from DynamoDB
 *
 * @author Zac Balson
 */
public class DynamoDBClientDetailsService implements ClientDetailsService {

    private final AmazonDynamoDB client;
    private final DynamoDBClientDetailsSchema schema;

    public DynamoDBClientDetailsService(AmazonDynamoDB client) {
        this(client, new DynamoDBClientDetailsSchema());
    }

    public DynamoDBClientDetailsService(AmazonDynamoDB client, DynamoDBClientDetailsSchema schema) {
        this.client = client;
        this.schema = schema;
    }

    @Override
    public ClientDetails loadClientByClientId(String clientId) throws ClientRegistrationException {
        GetItemResult result = client.getItem(schema.getTableName(), Collections.singletonMap(schema.getColumnClientId(), new AttributeValue(clientId)));
        
        Map<String, AttributeValue> item = result.getItem();
        if (item == null) { 
            throw new NoSuchClientException("Client: " + clientId + " not found.");
        }
        
        String resourceIds = DynamoDBUtils.nullSafeGetS(item.get(schema.getColumnResourceIds()));
        String scopes = DynamoDBUtils.nullSafeGetS(item.get(schema.getColumnScopes()));
        String grantTypes = DynamoDBUtils.nullSafeGetS(item.get(schema.getColumnAuthorizedGrantTypes()));
        String authorities = DynamoDBUtils.nullSafeGetS(item.get(schema.getColumnAuthorities()));
        String redirectUris = DynamoDBUtils.nullSafeGetS(item.get(schema.getColumnRegisteredRedirectUris()));
        
        String clientSecret = DynamoDBUtils.nullSafeGetS(item.get(schema.getColumnClientSecret()));
        
        ClientDetails clientDetails = createClientDetails(clientId, resourceIds, scopes, grantTypes, authorities, redirectUris, clientSecret, item);
        return clientDetails;
    }

    // A hook for creating a different [or enriched] ClientDetails]
    protected ClientDetails createClientDetails(String clientId, String resourceIds, String scopes, String grantTypes, String authorities, String redirectUris, String clientSecret, Map<String, AttributeValue> attributeValues) {
        BaseClientDetails cd = new BaseClientDetails(clientId, resourceIds, scopes, grantTypes, authorities, redirectUris);
        cd.setClientSecret(clientSecret);

        return cd;
    }
    
    public void saveOrUpdateClient(ClientDetails clientDetails) {
        Map<String, AttributeValueUpdate> updates = new HashMap<String, AttributeValueUpdate>();
        DynamoDBUtils.nullSafeUpdateS(updates, schema.getColumnResourceIds(), StringUtils.collectionToCommaDelimitedString(clientDetails.getResourceIds()));
        DynamoDBUtils.nullSafeUpdateS(updates, schema.getColumnScopes(), StringUtils.collectionToCommaDelimitedString(clientDetails.getScope()));
        DynamoDBUtils.nullSafeUpdateS(updates, schema.getColumnAuthorizedGrantTypes(), StringUtils.collectionToCommaDelimitedString(clientDetails.getAuthorizedGrantTypes()));
        DynamoDBUtils.nullSafeUpdateS(updates, schema.getColumnAuthorities(), StringUtils.collectionToCommaDelimitedString(AuthorityUtils.authorityListToSet(clientDetails.getAuthorities())));
        DynamoDBUtils.nullSafeUpdateS(updates, schema.getColumnRegisteredRedirectUris(), StringUtils.collectionToCommaDelimitedString(clientDetails.getRegisteredRedirectUri()));
        
        DynamoDBUtils.nullSafeUpdateS(updates, schema.getColumnClientSecret(), clientDetails.getClientSecret());
        
        enrichUpdates(updates, clientDetails);
        
        client.updateItem(schema.getTableName(), Collections.singletonMap(schema.getColumnClientId(), new AttributeValue(clientDetails.getClientId())), updates);
    }
    
    // A hook where additional fields from the user object can be added to the update list
    protected void enrichUpdates(Map<String, AttributeValueUpdate> updates, ClientDetails clientDetails) {
    }


}
