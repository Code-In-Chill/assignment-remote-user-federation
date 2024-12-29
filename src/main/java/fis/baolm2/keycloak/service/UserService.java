package fis.baolm2.keycloak.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import fis.baolm2.keycloak.dto.RemoteCountResponse;
import fis.baolm2.keycloak.dto.RemoteCredentialInput;
import fis.baolm2.keycloak.dto.RemoteUserEntity;
import fis.baolm2.keycloak.dto.RemoteVerifyPasswordResponse;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static fis.baolm2.keycloak.constant.RemoteUserStorageProviderConstants.*;

public class UserService {
    private final String UA = "Keycloak User Federation SPI";
    private final String findUserUrl;
    private final String verifyUserUrl;
    private final String searchUserUrl;
    private final String countUserUrl;
    private final String authorization_username;
    private final String authorization_password;
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final KeycloakSession session;

    public UserService(ComponentModel model, KeycloakSession session) {
        this.session = session;
        this.findUserUrl = model.get(REMOTE_PROVIDER_URL) + model.get(FIND_USER_ENDPOINT);
        this.verifyUserUrl = model.get(REMOTE_PROVIDER_URL) + model.get(VERIFY_USER_ENDPOINT);
        this.searchUserUrl = model.get(REMOTE_PROVIDER_URL) + model.get(SEARCH_USER_ENDPOINT);
        this.countUserUrl = model.get(REMOTE_PROVIDER_URL) + model.get(COUNT_USER_ENDPOINT);
        this.authorization_username = model.get(AUTHORIZATION_USERNAME);
        this.authorization_password = model.get(AUTHORIZATION_PASSWORD);
    }

    public List<RemoteUserEntity> searchUsers(Map<String, String> params, Integer firstResult, Integer maxResults) throws IOException {
        if (firstResult != null) {
            params.put("skip", String.valueOf(firstResult));
        }
        if (maxResults != null) {
            params.put("take", String.valueOf(maxResults));
        }
        try (SimpleHttp.Response response = doQuery(searchUserUrl, params)) {
            if (response.asString() == null) {
                return null;
            }
            return objectMapper.readValue(response.asString(), new TypeReference<>() {
            });
        }
    }

    public RemoteUserEntity getUser(Map<String, String> params) {
        try (SimpleHttp.Response response = doQuery(findUserUrl, params)) {
            if (response.asString() == null) {
                return null;
            }
            return objectMapper.readValue(response.asString(), RemoteUserEntity.class);
        } catch (Exception e) {
            return null;
        }
    }

    public RemoteUserEntity getUserById(String id) {
        Map<String, String> params = new HashMap<>() {{
            put("type", "id");
            put("id", id);
        }};
        return getUser(params);
    }

    public RemoteUserEntity getUserByUsername(String username) {
        Map<String, String> params = new HashMap<>() {{
            put("type", "username");
            put("username", username);
        }};
        return getUser(params);
    }

    public RemoteUserEntity getUserByEmail(String email) {
        Map<String, String> params = new HashMap<>() {{
            put("type", "email");
            put("email", email);
        }};
        return getUser(params);
    }

    public RemoteCountResponse getUserCount(Map<String, String> params) {
        try (SimpleHttp.Response response = doQuery(countUserUrl, params)) {
            if (response.asString() == null) {
                return new RemoteCountResponse(0);
            }
            return objectMapper.readValue(response.asString(), RemoteCountResponse.class);
        } catch (Exception e) {
            return new RemoteCountResponse(0);
        }
    }

    public RemoteVerifyPasswordResponse verifyPassword(String username, String password) throws IOException {
        RemoteCredentialInput input = new RemoteCredentialInput(username, password);
        try (SimpleHttp.Response response = SimpleHttp.doPost(verifyUserUrl, session)
                .header("User-Agent", UA)
                .authBasic(authorization_username, authorization_password)
                .json(input)
                .asResponse()) {
            if (response.asString() == null) {
                return new RemoteVerifyPasswordResponse(false);
            }
            return objectMapper.readValue(response.asString(), RemoteVerifyPasswordResponse.class);
        }
    }

    private SimpleHttp.Response doQuery(String url, Map<String, String> params) throws IOException {
        SimpleHttp simpleHttp = SimpleHttp.doGet(url, session).header("User-Agent", UA);
        if (authorization_username != null && !authorization_username.isEmpty()) {
            simpleHttp.authBasic(authorization_username, authorization_password);
        }
        for (Map.Entry<String, String> param : params.entrySet()) {
            simpleHttp.param(param.getKey(), param.getValue());
        }
        return simpleHttp.asResponse();
    }
}