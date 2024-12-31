package fis.baolm2.keycloak.provider.federation;

import fis.baolm2.keycloak.dto.RemoteUserEntity;
import org.jboss.logging.Logger;
import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.component.ComponentModel;
import org.keycloak.credential.UserCredentialManager;
import org.keycloak.models.*;
import org.keycloak.storage.StorageId;
import org.keycloak.storage.adapter.AbstractUserAdapterFederatedStorage;

import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static fis.baolm2.keycloak.constant.RemoteUserStorageProviderConstants.ADD_ROLES_TO_TOKEN;
import static fis.baolm2.keycloak.constant.RemoteUserStorageProviderConstants.DEBUG_ENABLED;

public class RemoteUserAdapter extends AbstractUserAdapterFederatedStorage {

    private static final Logger logger = Logger.getLogger(RemoteUserAdapter.class);

    // This model contains the configuration of the storage provider
    private final ComponentModel model;

    private final RemoteUserEntity user;
    private final String keycloakId;
    private final String username;

    public RemoteUserAdapter(ComponentModel model, KeycloakSession session, RealmModel realm, ComponentModel storageProviderModel, RemoteUserEntity user) {
        super(session, realm, storageProviderModel);
        this.user = user;
        this.keycloakId = StorageId.keycloakId(model, user.getId());
        this.username = user.getUserName();
        this.model = model;
    }

    @Override
    public SubjectCredentialManager credentialManager() {
        log("[credentialManager] new UserCredentialManager...");
        return new UserCredentialManager(session, realm, this);
    }

    @Override
    public String getId() {
        return keycloakId;
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public void setUsername(String s) {
        this.user.setUserName(s);
    }

    @Override
    public boolean isEmailVerified() {
        return user.isEmailVerified();
    }

    @Override
    public String getEmail() {
        return user.getEmail();
    }

    @Override
    public String getFirstName() {
        return user.getFirstName();
    }

    @Override
    public String getLastName() {
        return user.getLastName();
    }

    @Override
    public Map<String, List<String>> getAttributes() {
        MultivaluedHashMap<String, String> attributes = new MultivaluedHashMap<>();
        attributes.add(UserModel.USERNAME, getUsername());
        attributes.add(UserModel.EMAIL, getEmail());
        attributes.add(UserModel.FIRST_NAME, getFirstName());
        attributes.add(UserModel.LAST_NAME, getLastName());
        for (Map.Entry<String, String> param : user.getAttributes().entrySet()) {
            attributes.add(param.getKey(), param.getValue());
        }
        return attributes;
    }

    @Override
    public Stream<String> getAttributeStream(String name) {
        Map<String, List<String>> attributes = getAttributes();
        return (attributes.containsKey(name)) ? attributes.get(name).stream() : Stream.empty();
    }

    @Override
    public String getFirstAttribute(String name) {
        List<String> list = getAttributes().getOrDefault(name, List.of());
        return list.isEmpty() ? null : list.getFirst();
    }

    @Override
    public Stream<RoleModel> getRoleMappingsStream() {
        Stream<RoleModel> roleMappings = super.getRoleMappingsStream();
        boolean addFederationRoles = Boolean.parseBoolean(model.get(ADD_ROLES_TO_TOKEN));
        if (!addFederationRoles) {
            return roleMappings;
        }

        String[] roleArr = user.getRoles().split(",");
        for (String role : roleArr) {
            RoleModel roleModel = realm.getRole(role);
            if (roleModel == null) {
                roleModel = realm.addRole(role);
                log("Adding role %s", role);
            }
//            log("Granting role %s to user %s during user import from Remote", role, username);
//            this.grantRole(roleModel);
            roleMappings = Stream.concat(roleMappings, Stream.of(roleModel));
        }
        return roleMappings;
    }

    private void log(String message, Object... params) {
        if (Boolean.parseBoolean(model.get(DEBUG_ENABLED))) {
            logger.infof(message, params);
        }
    }
}
