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

package com.vivastream.dynamodb.core;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.util.Assert;

import com.amazonaws.services.dynamodbv2.AmazonDynamoDBClient;
import com.amazonaws.services.dynamodbv2.model.AttributeValue;
import com.amazonaws.services.dynamodbv2.model.AttributeValueUpdate;
import com.amazonaws.services.dynamodbv2.model.BatchGetItemResult;
import com.amazonaws.services.dynamodbv2.model.Condition;
import com.amazonaws.services.dynamodbv2.model.GetItemRequest;
import com.amazonaws.services.dynamodbv2.model.GetItemResult;
import com.amazonaws.services.dynamodbv2.model.KeysAndAttributes;
import com.amazonaws.services.dynamodbv2.model.QueryRequest;
import com.amazonaws.services.dynamodbv2.model.QueryResult;
import com.vivastream.dynamodb.exception.EmptyResultDataAccessException;
import com.vivastream.dynamodb.exception.IncorrectResultSizeDataAccessException;

/**
 * A wrapper around a AmazonDynamoDBClient to simply CRUD operations.  Could be enhanced
 * further to completely remove DynamoDB-specific types from the interface, but this
 * is sufficient for now.
 * 
 * @author Zac Balson
 */
public class DynamoDBTemplate {

    protected final Log logger = LogFactory.getLog(getClass());

    private final AmazonDynamoDBClient client;

    public DynamoDBTemplate(AmazonDynamoDBClient client) {
        Assert.notNull(client, "AmazonDynamoDBClient must not be null");
        this.client = client;
    }

    public <T> T get(String tableName, Map<String, AttributeValue> key, final ObjectExtractor<T> extractor, String... columnsToInclude) throws EmptyResultDataAccessException {
        Assert.notNull(tableName, "Table must not be null");
        Assert.notNull(extractor, "ObjectExtractor must not be null");
        if (logger.isDebugEnabled()) {
            logger.debug("Executing query on " + tableName + " for " + renderKey(key));
        }

        GetItemRequest request = new GetItemRequest(tableName, key, true);
        if (columnsToInclude != null && columnsToInclude.length > 0) {
            request.setAttributesToGet(Arrays.asList(columnsToInclude));
        }

        GetItemResult result = client.getItem(request);

        Map<String, AttributeValue> item = result.getItem();
        if (item == null) {
            throw new EmptyResultDataAccessException("No results found in " + tableName + "for " + renderKey(key));
        }

        return extractor.extract(item);
    }

    public <T> List<T> batchGet(String tableName, KeysAndAttributes keysAndAttributes, final ObjectExtractor<T> extractor) throws EmptyResultDataAccessException {
        Assert.notNull(tableName, "Table must not be null");
        Assert.notNull(extractor, "ObjectExtractor must not be null");
        if (logger.isDebugEnabled()) {
            logger.debug("Executing batch get on " + tableName + " for " + keysAndAttributes.toString());
        }

        List<T> results = new ArrayList<T>(keysAndAttributes.getKeys().size());

        Map<String, KeysAndAttributes> unprocessedKeys = Collections.singletonMap(tableName, keysAndAttributes);
        while (unprocessedKeys.size() > 0) {
            BatchGetItemResult result = client.batchGetItem(unprocessedKeys);
            List<Map<String, AttributeValue>> items = result.getResponses().get(tableName);
            if (items != null) {
                for (Map<String, AttributeValue> item : items) {
                    results.add(extractor.extract(item));
                }
            }

            unprocessedKeys = result.getUnprocessedKeys();
        }

        if (results.size() == 0) {
            throw new EmptyResultDataAccessException("No results found in " + tableName + "for " + keysAndAttributes.toString());
        }

        return results;
    }

    public <T> T queryUnique(String tableName, String indexName, Map<String, Condition> keyConditions, final ObjectExtractor<T> extractor, String... columnsToInclude) throws EmptyResultDataAccessException, IncorrectResultSizeDataAccessException {
        List<T> items = query(tableName, indexName, keyConditions, extractor, columnsToInclude);
        if (items.size() == 0) {
            throw new EmptyResultDataAccessException("No results found in " + tableName + "for " + renderKey(keyConditions));
        } else if (items.size() > 1) {
            throw new IncorrectResultSizeDataAccessException("Expecting 1 result for " + renderKey(keyConditions) + " but found " + items.size());
        }
        return items.iterator().next();
    }

    public <T> List<T> query(String tableName, String indexName, Map<String, Condition> keyConditions, final ObjectExtractor<T> extractor, String... columnsToInclude) throws EmptyResultDataAccessException {
        Assert.notNull(tableName, "Table must not be null");
        Assert.notNull(extractor, "ObjectExtractor must not be null");
        if (logger.isDebugEnabled()) {
            logger.debug("Executing query on " + tableName + " for " + renderKey(keyConditions));
        }

        QueryRequest request = new QueryRequest(tableName) //
                .withConsistentRead(false) // because query is used on GSIs [where consistent reads are not supported] - if we needed to query on the primary index could make this a parameter
                .withKeyConditions(keyConditions);

        if (columnsToInclude != null && columnsToInclude.length > 0) {
            request.setAttributesToGet(Arrays.asList(columnsToInclude));
        }

        if (indexName != null) {
            request.setIndexName(indexName);
        }

        QueryResult result = client.query(request);

        List<Map<String, AttributeValue>> items = result.getItems();
        List<T> convertedItems = new ArrayList<T>(items.size());
        for (Map<String, AttributeValue> item : items) {
            convertedItems.add(extractor.extract(item));
        }

        return convertedItems;
    }

    private static String renderKey(Map<String, ?> key) {
        return key.toString();
    }

    public void update(String tableName, Map<String, AttributeValue> key, Map<String, AttributeValueUpdate> updates) {
        client.updateItem(tableName, key, updates);
    }

    public void delete(String tableName, Map<String, AttributeValue> key) {
        client.deleteItem(tableName, key);
    }

}
