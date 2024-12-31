package fis.baolm2.keycloak.provider.federation;

import fis.baolm2.keycloak.dto.RemoteUserEntity;
import fis.baolm2.keycloak.dto.RemoteVerifyPasswordResponse;
import fis.baolm2.keycloak.service.UserService;
import org.jboss.logging.Logger;
import org.keycloak.component.ComponentModel;
import org.keycloak.credential.CredentialInput;
import org.keycloak.credential.CredentialInputValidator;
import org.keycloak.models.*;
import org.keycloak.models.credential.PasswordCredentialModel;
import org.keycloak.storage.StorageId;
import org.keycloak.storage.UserStorageProvider;
import org.keycloak.storage.user.UserLookupProvider;
import org.keycloak.storage.user.UserQueryProvider;
import org.keycloak.storage.user.UserRegistrationProvider;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

import static fis.baolm2.keycloak.constant.RemoteUserStorageProviderConstants.DEBUG_ENABLED;

/**
 * The RemoteUserProvider class is responsible for providing user storage, user lookup, user query, and credential input validation services. <br>
 * This class is used to interact with the remote user storage provider to perform operations such as user authentication, user search, and user retrieval.
 *
 * @author Le Minh Bao (baolm2)
 * @version 1.0
 * @since 1.0
 */
public class RemoteUserProvider implements UserStorageProvider,
        UserLookupProvider,
        UserQueryProvider,
        UserRegistrationProvider,
        CredentialInputValidator {

    private static final Logger logger = Logger.getLogger(RemoteUserProvider.class);

    private final KeycloakSession session;
    private final ComponentModel model;

    private final UserService userService;

    public RemoteUserProvider(KeycloakSession session, ComponentModel model, UserService userService) {
        this.session = session;
        this.model = model;
        this.userService = userService;
    }

    @Override
    public boolean supportsCredentialType(String credentialType) {
        return PasswordCredentialModel.TYPE.endsWith(credentialType);
    }

    @Override
    public boolean isConfiguredFor(RealmModel realm, UserModel user, String credentialType) {
        log("isConfiguredFor(realm=" + realm.getName() + ", user=" + user.getUsername() + ", credentialType=" + credentialType + ")");
        return true;
    }

    /**
     * Performs a remote password verification operation. <br>
     * This method sends a request to the remote server to verify the user's password.
     *
     * @param realm           The realm in which to which the credential belongs to
     * @param user            The user for which to test the credential
     * @param credentialInput the credential details to verify
     * @return {@code true} if the credential is valid, {@code false} otherwise.
     */
    @Override
    public boolean isValid(RealmModel realm, UserModel user, CredentialInput credentialInput) {
        log("isValid(realm=%s,user=%s,credentialInput.type=%s)",
                realm.getName(), user.getUsername(), credentialInput.getType());
        try {
            RemoteVerifyPasswordResponse response = userService.verifyPassword(user.getUsername(), credentialInput.getChallengeResponse());
            if (response == null) {
                log("Remote verify service response empty");
                return false;
            }
            log("Verify user [%s] result %s", user.getUsername(), response.isValid());
            return response.isValid();
        } catch (Exception e) {
            throw new RuntimeException("Remote server error:" + e.getMessage(), e);
        }
    }

    @Override
    public int getUsersCount(RealmModel realm) {
        log("Get users count");
        return userService.getUserCount(null).total();
    }

    @Override
    public int getUsersCount(RealmModel realm, Set<String> groupIds) {
        log("Get users count by group %s", groupIds);
        return userService.getUserCount(null).total();
    }

    @Override
    public int getUsersCount(RealmModel realm, Map<String, String> params) {
        log("Get users count by params %s", params);
        return userService.getUserCount(params).total();
    }

    @Override
    public int getUsersCount(RealmModel realm, Map<String, String> params, Set<String> groupIds) {
        log("Get users count by params and group %s, %s", params, groupIds);
        return userService.getUserCount(params).total();
    }

    @Override
    public int getUsersCount(RealmModel realm, boolean includeServiceAccount) {
        log("Get users count by includeServiceAccount");
        return userService.getUserCount(null).total();
    }

    @Override
    public void close() {
    }

    @Override
    public UserModel getUserById(RealmModel realm, String id) {
        log("Get user by id: %s", id);
        StorageId sid = new StorageId(id);
        return getUser(realm, "id", sid.getExternalId());
    }

    @Override
    public UserModel getUserByUsername(RealmModel realm, String username) {
        log("Get user by username %s", username);
        return getUser(realm, "username", username);
    }

    @Override
    public UserModel getUserByEmail(RealmModel realm, String email) {
        log("Get user by email %s", email);
        return getUser(realm, "email", email);
    }

    private UserModel getUser(RealmModel realm, String type, String search) {
        try {
            RemoteUserEntity userEntity = null;
            switch (type) {
                case "id": {
                    userEntity = userService.getUserById(search);
                    break;
                }
                case "username": {
                    userEntity = userService.getUserByUsername(search);
                    break;
                }
                case "email": {
                    userEntity = userService.getUserByEmail(search);
                    break;
                }
            }
            if (userEntity == null) {
                log("Remote user not found");
                return null;
            }
            log("Remote user %s", userEntity.toString());
            return mapUser(realm, userEntity);
        } catch (Exception e) {
            log("Remote server error %s", e.getMessage());
            return null;
        }
    }

    private UserModel mapUser(RealmModel realm, RemoteUserEntity userEntity) {
        return new RemoteUserAdapter(model, session, realm, model, userEntity);
    }

    @Override
    public Stream<UserModel> searchForUserStream(RealmModel realmModel, Map<String, String> params, Integer firstResult, Integer maxResults) {
        log("Search users: param=%s, firstResult=%d, maxResults=%d", params, firstResult, maxResults);
        try {
            if (!params.containsKey("method")) {
                params.put("method", "user");
            }
            List<RemoteUserEntity> userEntities = userService.searchUsers(params, firstResult, maxResults);
            return userEntities.stream().map(entity -> mapUser(realmModel, entity));
        } catch (IOException e) {
            log(e.getMessage());
            return Stream.empty();
        }
    }

    @Override
    public Stream<UserModel> searchForUserStream(RealmModel realm, Map<String, String> params) {
        return searchForUserStream(realm, params, null, null);
    }

    @Override
    public Stream<UserModel> getRoleMembersStream(RealmModel realm, RoleModel role) {
        Map<String, String> params = new HashMap<>() {{
            put("method", "role");
            put("role", role.getName());
        }};
        return searchForUserStream(realm, params, null, null);
    }

    @Override
    public Stream<UserModel> getRoleMembersStream(RealmModel realm, RoleModel role, Integer firstResult, Integer maxResults) {
        Map<String, String> params = new HashMap<>() {{
            put("method", "role");
            put("role", role.getName());
        }};
        return searchForUserStream(realm, params, firstResult, maxResults);
    }

    /**
     * Returns empty stream as the remote user provider does not support group membership.
     *
     * @param realm a reference to the realm.
     * @param group a reference to the group.
     * @return an empty stream.
     */
    @Override
    public Stream<UserModel> getGroupMembersStream(RealmModel realm, GroupModel group) {
        return Stream.empty();
    }

    /**
     * Returns empty stream as the remote user provider does not support group membership.
     *
     * @param realmModel a reference to the realm.
     * @param groupModel a reference to the group.
     * @param integer    first result to return. Ignored if negative, zero, or {@code null}.
     * @param integer1   maximum number of results to return. Ignored if negative or {@code null}.
     * @return an empty stream.
     */
    @Override
    public Stream<UserModel> getGroupMembersStream(RealmModel realmModel, GroupModel groupModel, Integer integer, Integer integer1) {
        return Stream.empty();
    }

    /**
     * Returns empty stream as the remote user provider does not support group membership.
     *
     * @param realmModel a reference to the realm.
     * @param s          the attribute name.
     * @param s1         the attribute value.
     * @return an empty stream.
     */
    @Override
    public Stream<UserModel> searchForUserByUserAttributeStream(RealmModel realmModel, String s, String s1) {
        return Stream.empty();
    }

    /**
     * Logs a message indicating that the realm is about to be removed. <br>
     * As the remote user provider does not need to perform any cleanup operations, this method does nothing.
     *
     * @param realm a reference to the realm.
     */
    @Override
    public void preRemove(RealmModel realm) {
        log("pre-remove realm");
    }

    /**
     * Logs a message indicating that the group is about to be removed. <br>
     * As the remote user provider does not need to perform any cleanup operations, this method does nothing.
     *
     * @param realm a reference to the realm.
     * @param group a reference to the group.
     */
    @Override
    public void preRemove(RealmModel realm, GroupModel group) {
        log("pre-remove group");
    }

    /**
     * Logs a message indicating that the role is about to be removed. <br>
     * As the remote user provider does not need to perform any cleanup operations, this method does nothing.
     *
     * @param realm a reference to the realm.
     * @param role  a reference to the role.
     */
    @Override
    public void preRemove(RealmModel realm, RoleModel role) {
        log("pre-remove role");
    }

    private void log(String message, Object... params) {
        if (Boolean.parseBoolean(model.get(DEBUG_ENABLED))) {
            logger.infof(message, params);
        }
    }

    @Override
    public UserModel addUser(RealmModel realm, String username) {
        return null;
    }

    @Override
    public boolean removeUser(RealmModel realm, UserModel user) {
        return false;
    }
}
