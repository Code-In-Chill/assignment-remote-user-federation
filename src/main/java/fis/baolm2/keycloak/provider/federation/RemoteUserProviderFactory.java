package fis.baolm2.keycloak.provider.federation;

import fis.baolm2.keycloak.service.UserService;
import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.component.ComponentModel;
import org.keycloak.component.ComponentValidationException;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;
import org.keycloak.storage.UserStorageProvider;
import org.keycloak.storage.UserStorageProviderFactory;

import java.util.List;

import static fis.baolm2.keycloak.constant.RemoteUserStorageProviderConstants.*;

public class RemoteUserProviderFactory implements UserStorageProviderFactory<RemoteUserProvider> {

    private static final Logger logger = Logger.getLogger(RemoteUserProviderFactory.class);
    protected final List<ProviderConfigProperty> configMetadata;

    public RemoteUserProviderFactory() {
        this.configMetadata = ProviderConfigurationBuilder.create()
                .property().name(REMOTE_PROVIDER_URL).label("Remote Server").type(ProviderConfigProperty.STRING_TYPE).defaultValue("https://").helpText("If this keycloak running in a docker container, you can use `http://host.docker.internal:port` to access the provider on your local machine.").required(true).add()
                .property().name(AUTHORIZATION_USERNAME).label("Authorization Username").type(ProviderConfigProperty.STRING_TYPE).defaultValue("admin").helpText("Authorization header value to access the remote server.").required(true).add()
                .property().name(AUTHORIZATION_PASSWORD).label("Authorization Password").type(ProviderConfigProperty.PASSWORD).defaultValue("admin").helpText("Authorization header value to access the remote server. This password will be hidden after you create provider.").required(true).secret(true).add()
                .property().name(FIND_USER_ENDPOINT).label("Find User Endpoint").type(ProviderConfigProperty.STRING_TYPE).defaultValue("/users").helpText("Endpoint to find a user by username.").required(true).add()
                .property().name(VERIFY_USER_ENDPOINT).label("Verify User Endpoint").type(ProviderConfigProperty.STRING_TYPE).defaultValue("/auth").helpText("Endpoint to verify a user's password.").required(true).add()
                .property().name(SEARCH_USER_ENDPOINT).label("Search User Endpoint").type(ProviderConfigProperty.STRING_TYPE).defaultValue("/users").helpText("Endpoint to search users.").required(true).add()
                .property().name(COUNT_USER_ENDPOINT).label("Count User Endpoint").type(ProviderConfigProperty.STRING_TYPE).defaultValue("/users/count").helpText("Endpoint to count users.").required(true).add()
                .property().name(ADD_ROLES_TO_TOKEN).label("Add Roles to Token").type(ProviderConfigProperty.BOOLEAN_TYPE).defaultValue(true).helpText("Add roles to token. This will help you to use roles in your application.").required(true).add()
                .property().name(DEBUG_ENABLED).label("Enable Detail Logs").type(ProviderConfigProperty.BOOLEAN_TYPE).defaultValue(false).helpText("Enable detail logs to debug.").required(true).add()
                .build();
    }

    @Override
    public RemoteUserProvider create(KeycloakSession session, ComponentModel model) {
        return new RemoteUserProvider(session, model, new UserService(model, session));
    }

    @Override
    public UserStorageProvider create(KeycloakSession session) {
        return UserStorageProviderFactory.super.create(session);
    }

    @Override
    public String getId() {
        return PROVIDER_NAME;
    }

    @Override
    public int order() {
        return UserStorageProviderFactory.super.order();
    }

    @Override
    public List<ProviderConfigProperty> getConfigMetadata() {
        return UserStorageProviderFactory.super.getConfigMetadata();
    }

    @Override
    public void init(Config.Scope config) {
        UserStorageProviderFactory.super.init(config);
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        UserStorageProviderFactory.super.postInit(factory);
    }

    @Override
    public void close() {
        UserStorageProviderFactory.super.close();
    }

    @Override
    public String getHelpText() {
        return UserStorageProviderFactory.super.getHelpText();
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configMetadata;
    }

    @Override
    public <C> C getConfig() {
        return UserStorageProviderFactory.super.getConfig();
    }

    @Override
    public void validateConfiguration(KeycloakSession session, RealmModel realm, ComponentModel config) throws ComponentValidationException {
        boolean valid = true;
        String comment = "";

        final String url = config.get(REMOTE_PROVIDER_URL);
        if (url != null && url.length() < URL_MIN_LENGTH) {
            valid = false;
            comment = "Please check the url.";
        }
        if (!valid) {
            throw new ComponentValidationException("Unable to validate configuration. Err: " + comment);
        }
    }

    @Override
    public void onCreate(KeycloakSession session, RealmModel realm, ComponentModel model) {

    }

    @Override
    public void onUpdate(KeycloakSession session, RealmModel realm, ComponentModel oldModel, ComponentModel newModel) {

    }
}
