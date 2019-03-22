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

package com.vivastream.security.oauth2.common.util;

import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.amazonaws.services.dynamodbv2.model.AttributeDefinition;
import com.amazonaws.services.dynamodbv2.model.CreateTableRequest;
import com.amazonaws.services.dynamodbv2.model.CreateTableResult;
import com.amazonaws.services.dynamodbv2.model.GlobalSecondaryIndex;
import com.amazonaws.services.dynamodbv2.model.KeySchemaElement;
import com.amazonaws.services.dynamodbv2.model.KeyType;
import com.amazonaws.services.dynamodbv2.model.Projection;
import com.amazonaws.services.dynamodbv2.model.ProjectionType;
import com.amazonaws.services.dynamodbv2.model.ProvisionedThroughput;
import com.amazonaws.services.dynamodbv2.model.ScalarAttributeType;
import com.vivastream.security.oauth2.provider.DynamoDBClientDetailsSchema;
import com.vivastream.security.oauth2.provider.DynamoDBUserDetailsSchema;
import com.vivastream.security.oauth2.provider.token.store.DynamoDBTokenSchema;

/**
 * Helper methods for creating the DynamoDB tables needed for oauth2 support
 * 
 * @author Zac Balson
 */
public class DynamoDBInitializationHelper {

    private static final ProvisionedThroughput DEFAULT_PROVISIONED_THROUGHPUT = new ProvisionedThroughput(5l, 5l);

    public static void createTokenTables(AmazonDynamoDB client, DynamoDBTokenSchema schema) {
        GlobalSecondaryIndex gsiAuthenticationIdToken = new GlobalSecondaryIndex() //
                .withIndexName(schema.getAccessIndexAuthenticationId()) //
                .withKeySchema(new KeySchemaElement(schema.getAccessColumnAuthenticationId(), KeyType.HASH)) //
                .withProvisionedThroughput(DEFAULT_PROVISIONED_THROUGHPUT) //
                .withProjection(new Projection().withProjectionType(ProjectionType.KEYS_ONLY));

        GlobalSecondaryIndex gsiRefreshToken = new GlobalSecondaryIndex() //
                .withIndexName(schema.getAccessIndexRefreshToken()) //
                .withKeySchema(new KeySchemaElement(schema.getAccessColumnRefreshToken(), KeyType.HASH)) //
                .withProvisionedThroughput(DEFAULT_PROVISIONED_THROUGHPUT) //
                .withProjection(new Projection().withProjectionType(ProjectionType.KEYS_ONLY));

        GlobalSecondaryIndex gsiClientIdAndUserName = new GlobalSecondaryIndex() //
                .withIndexName(schema.getAccessIndexClientIdAndUserName()) //
                .withKeySchema( //
                        new KeySchemaElement(schema.getAccessColumnClientId(), KeyType.HASH), //
                        new KeySchemaElement(schema.getAccessColumnUserName(), KeyType.RANGE) //
                ) //
                .withProvisionedThroughput(DEFAULT_PROVISIONED_THROUGHPUT) //
                .withProjection(new Projection().withProjectionType(ProjectionType.KEYS_ONLY));

        CreateTableRequest accessTableRequest = new CreateTableRequest() //
                .withTableName(schema.getAccessTableName()) //
                .withKeySchema(new KeySchemaElement(schema.getAccessColumnTokenId(), KeyType.HASH)) //
                .withGlobalSecondaryIndexes(gsiAuthenticationIdToken, gsiRefreshToken, gsiClientIdAndUserName) //
                .withAttributeDefinitions(new AttributeDefinition(schema.getAccessColumnTokenId(), ScalarAttributeType.S), //
                        new AttributeDefinition(schema.getAccessColumnAuthenticationId(), ScalarAttributeType.S), //
                        new AttributeDefinition(schema.getAccessColumnRefreshToken(), ScalarAttributeType.S), //
                        new AttributeDefinition(schema.getAccessColumnClientId(), ScalarAttributeType.S), //
                        new AttributeDefinition(schema.getAccessColumnUserName(), ScalarAttributeType.S) //
                ) //
                .withProvisionedThroughput(DEFAULT_PROVISIONED_THROUGHPUT) //
        ;

        CreateTableResult accessTableResponse = client.createTable(accessTableRequest);

        CreateTableRequest refreshTableRequest = new CreateTableRequest() //
                .withTableName(schema.getRefreshTableName()) //
                .withKeySchema(new KeySchemaElement(schema.getRefreshColumnTokenId(), KeyType.HASH)) //
                .withAttributeDefinitions(new AttributeDefinition(schema.getRefreshColumnTokenId(), ScalarAttributeType.S) //
                ) //
                .withProvisionedThroughput(DEFAULT_PROVISIONED_THROUGHPUT) //
        ;

        CreateTableResult refreshTableresponse = client.createTable(refreshTableRequest);
    }

    public static void createUserDetailsTable(AmazonDynamoDB client, DynamoDBUserDetailsSchema schema) {
        createHashTable(client, schema.getTableName(), schema.getColumnUsername());
    }

    public static void createClientDetailsTable(AmazonDynamoDB client, DynamoDBClientDetailsSchema schema) {
        createHashTable(client, schema.getTableName(), schema.getColumnClientId());
    }

    public static void createHashTable(AmazonDynamoDB client, String tableName, String hashColumnName) {

        CreateTableRequest accessTableRequest = new CreateTableRequest() //
                .withTableName(tableName) //
                .withKeySchema(new KeySchemaElement(hashColumnName, KeyType.HASH)) //
                .withAttributeDefinitions(new AttributeDefinition(hashColumnName, ScalarAttributeType.S) //
                ) //
                .withProvisionedThroughput(DEFAULT_PROVISIONED_THROUGHPUT) //
        ;

        CreateTableResult accessTableResponse = client.createTable(accessTableRequest);
    }

}
