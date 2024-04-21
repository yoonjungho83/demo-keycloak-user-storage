package com.keycloak.userstorage.provider;

import java.sql.Connection;
import java.util.List;

import org.keycloak.component.ComponentModel;
import org.keycloak.component.ComponentValidationException;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;
import org.keycloak.storage.UserStorageProviderFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.keycloak.userstorage.config.CommonConstants;
import com.keycloak.userstorage.external.DbUtil;

import lombok.extern.slf4j.Slf4j;

/** create by clubbboy@naver.com
 * Keycloak이 사용자 정의 사용자 저장소에 액세스하도록 허용합니다.
 */
@Slf4j
public class ExternalUserStorageProviderFactory implements UserStorageProviderFactory<ExternalUserStorageProvider> {
    
	public    final String providerName = "external-user-privider";
    protected final List<ProviderConfigProperty> configMetadata;
    
    
    
    public ExternalUserStorageProviderFactory() {
        log.info("[ExternalUserStorageProviderFactory] ExternalUserStorageProviderFactory created");
        
        
        // Create config metadata
        configMetadata = ProviderConfigurationBuilder.create()
          .property()
            .name(CommonConstants.CONFIG_KEY_JDBC_DRIVER)
            .label("JDBC Driver Class")
            .type(ProviderConfigProperty.STRING_TYPE)
            .defaultValue("org.mariadb.jdbc.Driver")
            .helpText("Fully qualified class name of the JDBC driver")
            .add()
          .property()
            .name(CommonConstants.CONFIG_KEY_JDBC_URL)
            .label("JDBC URL")
            .type(ProviderConfigProperty.STRING_TYPE)
            .defaultValue("jdbc:mariadb://localhost:3306/legacy_db")
            .helpText("JDBC URL used to connect to the user database")
            .add()
          .property()
            .name(CommonConstants.CONFIG_KEY_DB_USERNAME)
            .label("Database User")
            .type(ProviderConfigProperty.STRING_TYPE)
            .helpText("Username used to connect to the database")
            .add()
          .property()
            .name(CommonConstants.CONFIG_KEY_DB_PASSWORD)
            .label("Database Password")
            .type(ProviderConfigProperty.PASSWORD)
            .helpText("Password used to connect to the database")
            .secret(true)
            .add()
          .property()
            .name(CommonConstants.CONFIG_KEY_VALIDATION_QUERY)
            .label("SQL Validation Query")
            .type(ProviderConfigProperty.STRING_TYPE)
            .helpText("SQL query used to validate a connection")
            .defaultValue("select 1 ")
            .add()
          .build();   
          
    }

    /**
     * 트랜잭션이 일어날때마다 생성되고 종료됨.
     */
    @Override
    public ExternalUserStorageProvider create(KeycloakSession ksession, ComponentModel model) {
        log.info("[ExternalUserStorageProviderFactory] creating new ExternalUserStorageProvider");
        return new ExternalUserStorageProvider(ksession,model);
    }

    /**
     * keycloak 관리 페이지에 표시할 공급자의 고유 식별자 이름. admin page의 spi 이름.
     */
    @Override
    public String getId() {
        log.info("[ExternalUserStorageProviderFactory] getId()");
        return this.providerName;
    }

    
    // Configuration support methods
    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
    	log.info("[ExternalUserStorageProviderFactory] getConfigProperties()");
        return configMetadata;
    }

    @Override
    public void validateConfiguration(KeycloakSession session, RealmModel realm, ComponentModel config) throws ComponentValidationException {
    	
    	log.info("[ExternalUserStorageProviderFactory] validateConfiguration start" );
       try (Connection c = DbUtil.getConnection(config)) 
       {
           log.info("[ExternalUserStorageProviderFactory] Testing connection..." );
           c.createStatement().execute(config.get(CommonConstants.CONFIG_KEY_VALIDATION_QUERY));
           log.info("[ExternalUserStorageProviderFactory] Connection OK !" );
       }
       catch(Exception ex) {
           log.error("[ExternalUserStorageProviderFactory Error] Unable to validate connection: ex={}", ex.getMessage());
           throw new ComponentValidationException("Unable to validate database connection",ex);
       }
       log.info("[ExternalUserStorageProviderFactory] validateConfiguration end" );
    }

}
