package de.soapbubbles.keycloak.joomlauserstorage;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.List;
import java.util.Map;

import org.jboss.logging.Logger;
import org.keycloak.component.ComponentModel;
import org.keycloak.credential.CredentialInput;
import org.keycloak.credential.CredentialInputValidator;
import org.keycloak.models.GroupModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.PasswordCredentialModel;
import org.keycloak.storage.StorageId;
import org.keycloak.storage.UserStorageProvider;
import org.keycloak.storage.adapter.AbstractUserAdapter;
import org.keycloak.storage.user.UserLookupProvider;
import org.keycloak.storage.user.UserQueryProvider;
import org.mindrot.jbcrypt.BCrypt;

public class JoomlaUserStorageProvider 
    implements UserStorageProvider, UserLookupProvider, CredentialInputValidator, UserQueryProvider {

    private ComponentModel config;
    private KeycloakSession session;
    private Connection connection;

    private static final Logger logger = Logger.getLogger(JoomlaUserStorageProvider.class);

    private static final String SQL_GET_USER_BY_EMAIL    = "SELECT id, name, username, email, password, block FROM $tableName where email = ?";
    private static final String SQL_GET_USER_COUNT    = "SELECT count(id) as count FROM $tableName Where block = 0";

    public JoomlaUserStorageProvider(KeycloakSession session, ComponentModel config, Connection connection) {
        this.session = session;
        this.config = config;
        this.connection = connection;
    }

    /**
    * @param query
    * @param filterParameter
    * @param realm
    * @return List<UserModel>
    */
    protected UserModel getUserWithFilter(String query, String filterParemeter, RealmModel realm){
        Statement stmt = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        UserModel adapter = null;
        try {
            ps = connection.prepareStatement(query);
            ps.setString(1, filterParemeter);
            rs = ps.executeQuery();
            if (rs.next()) {
                adapter = createAdapter(realm, 
                    rs.getString("id"),
                    rs.getString("username"),
                    rs.getString("email"),
                    rs.getString("name"),
                    !rs.getBoolean("block"),
                    rs.getString("password")
                );
            }
        } catch (SQLException ex) {
            logger.error("SQLException: " + ex.getMessage());
            logger.error("SQLState: " + ex.getSQLState());
            logger.error("VendorError: " + ex.getErrorCode());
        } finally {
            if (ps != null) {
                try {
                    ps.close();
                } catch (SQLException sqlEx) {
                }
                rs = null;
            }

            if (rs != null) {
                try {
                    rs.close();
                } catch (SQLException sqlEx) {
                }
                rs = null;
            }

            if (stmt != null) {
                try {
                    stmt.close();
                } catch (SQLException sqlEx) {
                }
                stmt = null;
            }
        }
        return adapter;
    }

    /**
     * 
     * @param query
     * @param username
     * @return String
     */
    protected String getUserPasswordHash(String query, String username){
        PreparedStatement ps = null;
        ResultSet rs = null;
        String password = null;
        try{
            ps = connection.prepareStatement(query);
            ps.setString(1, username);
            rs = ps.executeQuery();
            if(rs.next()){
                password = rs.getString("password");
            }
        } catch(SQLException ex) {
            logger.error("SQLException: " + ex.getMessage());
            logger.error("SQLState: " + ex.getSQLState());
            logger.error("VendorError: " + ex.getErrorCode());
        } finally{
            if(rs != null){
                try{
                    rs.close();
                } catch(SQLException sqlEx) {

                }
                rs = null;
            }
            if(ps != null){
                try{
                    ps.close();
                } catch(SQLException sqlEx) {

                }
                ps = null;
            }
        }
        return password;
    }

    /**
     * @param query
     * @param tableName
     * @return String
     */
    protected String setTableNameToQuery(String query, String tableName) {
        return query.replace("$tableName", this.config.getConfig().getFirst("prefix") + tableName);
    }

    /**
     * @param realm
     * @param id
     * @param username
     * @param email
     * @param name
     * @param isEnabled
     * @param password
     * @return UserModel
     */
    protected UserModel createAdapter(RealmModel realm, String id, String username, String email, String name, boolean isEnabled, String password) {
        return new AbstractUserAdapter(session, realm, config) {
            @Override
            public String getUsername() {
                return email;
            }
            @Override
            public String getFirstName() {
                return name.substring(0, name.indexOf(" ")+1);
            }
            @Override
            public String getLastName() {
                return name.substring(name.indexOf(" "));
            }
            @Override
            public String getEmail(){
                return email;
            }            
            @Override
            public boolean isEnabled() {
                return isEnabled;
            }
        };
    }

    /**
     * @param username
     * @param realm
     * @return UserModel
     */
    @Override
    public UserModel getUserByUsername(String username, RealmModel realm) {
        return getUserWithFilter(
            setTableNameToQuery(SQL_GET_USER_BY_EMAIL, "users"), 
            username, 
            realm);
    }

    /**
     * @param credentialType
     * @return boolean
     */
    @Override
    public boolean supportsCredentialType(String credentialType) {
        return credentialType.equals(PasswordCredentialModel.TYPE);
    }
    
    /**
     * @param realm
     * @param user
     * @param credentialType
     * @return boolean
     */
    @Override
    public boolean isConfiguredFor(RealmModel realm, UserModel user, String credentialType) {
        try{
            String password = getUserPasswordHash(
                setTableNameToQuery(SQL_GET_USER_BY_EMAIL, "users"), 
                user.getUsername()
            );

            return credentialType.equals(PasswordCredentialModel.TYPE) && password != null;
        }
        catch(Exception ex){
            logger.error(ex.getMessage());
        }
        return false;
    }
    
    /**
     * @param realm
     * @param user
     * @param input
     * @return boolean
     */
    @Override
    public boolean isValid(RealmModel realm, UserModel user, CredentialInput input) {
        try{
            if(!supportsCredentialType(input.getType())){
                return false;
            }

            String passwordHash = getUserPasswordHash(
                setTableNameToQuery(SQL_GET_USER_BY_EMAIL, "users"), 
                user.getUsername()
            );

            if(passwordHash.startsWith("$2y$")){
                passwordHash = passwordHash.substring(0,2) + "a" + passwordHash.substring(3);
            }

            return BCrypt.checkpw(input.getChallengeResponse(), passwordHash);
        
        } catch(Exception ex){
            
            logger.error(ex.getMessage());
        
        }
        
        return false;
    }
    
    /**
     * @param id
     * @param realm
     * @return UserModel
     */
    @Override
    public UserModel getUserById(String id, RealmModel realm) {
        StorageId storageId = new StorageId(id);
        String username = storageId.getExternalId();
        return getUserByUsername(username, realm);
    }
    
    /**
     * @param email
     * @param realm
     * @return UserModel
     */
    @Override
    public UserModel getUserByEmail(String email, RealmModel realm) {
        return null;
    }

    @Override
    public void close() {
        // TODO Auto-generated method stub
        
    }

    @Override
    public List<UserModel> getUsers(RealmModel realm) {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public List<UserModel> getUsers(RealmModel realm, int firstResult, int maxResults) {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public List<UserModel> searchForUser(String search, RealmModel realm) {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public List<UserModel> searchForUser(String search, RealmModel realm, int firstResult, int maxResults) {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public List<UserModel> searchForUser(Map<String, String> params, RealmModel realm) {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public List<UserModel> searchForUser(Map<String, String> params, RealmModel realm, int firstResult,
            int maxResults) {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public List<UserModel> getGroupMembers(RealmModel realm, GroupModel group) {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public List<UserModel> getGroupMembers(RealmModel realm, GroupModel group, int firstResult, int maxResults) {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public List<UserModel> searchForUserByUserAttribute(String attrName, String attrValue, RealmModel realm) {
        // TODO Auto-generated method stub
        return null;
    }

    /**
     * @param realm
     * @param boolean
     * @return int
     */
    @Override
    public int getUsersCount(RealmModel realm, boolean includeServiceAccount) {
        String query = setTableNameToQuery(SQL_GET_USER_COUNT, "users");
        Statement stmt = null;
        ResultSet rs = null;
        int count = 0;
        try{
            stmt = connection.createStatement();            
            rs = stmt.executeQuery(query);
            if(rs.next()){
                count = rs.getInt("count");
            }
        } catch(SQLException ex) {
            logger.error("SQLException: " + ex.getMessage());
            logger.error("SQLState: " + ex.getSQLState());
            logger.error("VendorError: " + ex.getErrorCode());
        } finally{
            if(rs != null){
                try{
                    rs.close();
                } catch(SQLException sqlEx) {

                }
                rs = null;
            }
            if(stmt != null){
                try{
                    stmt.close();
                } catch(SQLException sqlEx) {

                }
                stmt = null;
            }
        }
        return count;
    }
}
