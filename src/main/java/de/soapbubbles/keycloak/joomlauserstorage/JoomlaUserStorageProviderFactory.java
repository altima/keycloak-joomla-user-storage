package de.soapbubbles.keycloak.joomlauserstorage;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.List;
import org.jboss.logging.Logger;
import org.keycloak.component.ComponentModel;
import org.keycloak.component.ComponentValidationException;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;
import org.keycloak.storage.UserStorageProviderFactory;

public class JoomlaUserStorageProviderFactory
    implements UserStorageProviderFactory<JoomlaUserStorageProvider> {

    private static final Logger logger = Logger.getLogger(JoomlaUserStorageProviderFactory.class);
    protected static final List<ProviderConfigProperty> configMetadata;
    protected static final String PROVIDER_NAME = "joomla-users";
    protected static final Integer CONNECTION_TIMEOUT = 1000;

    static {
        configMetadata = ProviderConfigurationBuilder.create()
            .property().name("dbhost").type(ProviderConfigProperty.STRING_TYPE).label("Database Host")
                .defaultValue("joomla-db:3306")
                .helpText("MySQL URI")
                .add()
            .property().name("dbuser").type(ProviderConfigProperty.STRING_TYPE).label("Database User")
                .defaultValue("joomla")
                .helpText("The database user")
                .add()
            .property().name("dbpass").type(ProviderConfigProperty.STRING_TYPE).label("Database Password")
                .defaultValue("joomla")
                .helpText("The database user password")
                .add()
            .property().name("dbname").type(ProviderConfigProperty.STRING_TYPE).label("Database Name")
                .defaultValue("joomla-db")
                .helpText("The database name")
                .add()
            .property().name("prefix").type(ProviderConfigProperty.STRING_TYPE).label("The prefix configured in Joomla")
                .defaultValue("j3u0q_")
                .helpText("Prefix for the Joomla tables")
                .add()
            
            .build();
    }

    /**
     * @return List<ProviderConfigProperty>
     */
    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configMetadata;
    }

    /**
     * @param sessiond
     * @param realm
     * @param config
     * @throws ComponentValidationException
     */
    @Override
    public void validateConfiguration(KeycloakSession session, RealmModel realm, ComponentModel config)
            throws ComponentValidationException {
        String dbhost = config.getConfig().getFirst("dbhost");
        String dbname = config.getConfig().getFirst("dbname");
        if (dbhost == null || dbname == null) {
            throw new ComponentValidationException("Database host or database name not configured!");
        }
        String dbuser = config.getConfig().getFirst("dbuser");
        String dbpass = config.getConfig().getFirst("dbpass");
        if (dbuser == null || dbpass == null) {
            throw new ComponentValidationException("Database crednetials wrong or not set!");
        }
        String uri = String.format("jdbc:mysql://%s/%s", dbhost, dbname);
        Connection conn = null;
        try {
            conn = DriverManager.getConnection(uri, dbuser, dbpass);
            conn.isValid(CONNECTION_TIMEOUT);
        } catch (SQLException ex) {
            // handle any errors
            logger.error("SQLException: " + ex.getMessage());
            logger.error("SQLState: " + ex.getSQLState());
            logger.error("VendorError: " + ex.getErrorCode());
            throw new ComponentValidationException(ex.getMessage());
        }
    }

    /**
     * @param session
     * @param config
     * @return JoomlaUserStorageProvider
     */
    @Override
    public JoomlaUserStorageProvider create(KeycloakSession session, ComponentModel config) {
        String dbhost = config.getConfig().getFirst("dbhost");
        String dbname = config.getConfig().getFirst("dbname");
        String dbuser = config.getConfig().getFirst("dbuser");
        String dbpass = config.getConfig().getFirst("dbpass");
        String uri = String.format("jdbc:mysql://%s/%s", dbhost, dbname);
        Connection conn = null;
        try {
            conn = DriverManager.getConnection(uri, dbuser, dbpass);
        } catch (SQLException ex) {
            // handle any errors
            logger.error("SQLException: " + ex.getMessage());
            logger.error("SQLState: " + ex.getSQLState());
            logger.error("VendorError: " + ex.getErrorCode());
            throw new ComponentValidationException(ex.getMessage());
        }

        return new JoomlaUserStorageProvider(session, config, conn);
    }

    /**
     * @return String
     */
    @Override
    public String getId() {
        return PROVIDER_NAME;
    }
}
