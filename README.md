spring-security-oauth2-dynamodb
===============================

The primary purpose of this project is:
* to provide a DynamoDB-backed implementation of org.springframework.security.oauth2.provider.token.TokenStore, aptly named DynamoDBTokenStore

Secondarily, simple DynamoDB-backed implementations are provided for:
* ClientDetails [via DynamoDBClientDetailsService]
* UserDetails [via DynamoDBUserDetailsManager]

To be clear, this is *NOT* an official part of spring-security-oauth.  Rather it is simply a convenience library for using Spring OAuth2 with DynamoDB persistence (instead of the built in JDBC or InMemory implementations).

## Usage

Once this library is linked, these beans can be wired up in the applicationContext.xml by:
```
  <context:property-placeholder location="[path to aws properties file]"
    ignore-unresolvable="false" system-properties-mode="OVERRIDE" />

  <!-- AWS Client Config -->
  <bean id="amazonDynamoDBClient" class="com.amazonaws.services.dynamodbv2.AmazonDynamoDBClient">
    <constructor-arg ref="amazonAWSCredentials" />
    <property name="endpoint" value="${amazon.dynamodb.endpoint}" />
  </bean>

  <bean id="amazonAWSCredentials" class="com.amazonaws.auth.BasicAWSCredentials">
    <constructor-arg value="${amazon.aws.accesskey}" />
    <constructor-arg value="${amazon.aws.secretkey}" />
  </bean>

  <bean id="tokenStore" class="com.vivastream.security.oauth2.provider.token.store.DynamoDBTokenStore">
    <constructor-arg ref="amazonDynamoDBClient" />
  </bean>

  <bean id="clientDetailsService" class="com.vivastream.security.oauth2.provider.DynamoDBClientDetailsService">
    <constructor-arg ref="amazonDynamoDBClient" />
  </bean>

  <bean id="userDetailsManager" class="com.vivastream.security.oauth2.provider.DynamoDBUserDetailsManager">
    <constructor-arg ref="amazonDynamoDBClient" />
    <!-- Should really set auth manager on this as well, for re-authentication on changePassword(...) -->
  </bean>
```

This assumes a properties file has been provided with
```
amazon.aws.accesskey=YOUR_AWS_KEY
amazon.aws.secretkey=YOUR_AWS_SECRET
amazon.dynamodb.endpoint=YOUR_DESIRED_ENDPOINT
```

Optionally, the table/column name can be customized by way of the corresponding Schema beans, e.g.:
```
  <!-- DynamoDB-backed Token Config -->  
  <bean id="tokenSchema" class="com.vivastream.security.oauth2.provider.token.store.DynamoDBTokenSchema">
    <property name="accessTableName" value="YOUR_ACCESS_TOKEN_TABLE" />
    <property name="refreshTableName" value="YOUR_REFRESH_TOKEN_TABLE" />
  </bean>
  ...
  <bean id="tokenStore" class="com.vivastream.security.oauth2.provider.token.store.DynamoDBTokenStore">
    <constructor-arg ref="amazonDynamoDBClient" />
    <constructor-arg ref="tokenSchema" />
  </bean>
```