package fis.baolm2.keycloak.dto;

import java.util.Map;

public class RemoteUserEntity {
    private String id;
    private String firstName;
    private String lastName;
    private String userName;
    private String email;
    private boolean emailVerified;
    private boolean enabled;
    private String createdAt;
    private Map<String, String> attributes;
    private String roles;

    public RemoteUserEntity() {
    }

    public RemoteUserEntity(String id, String firstName, String lastName, String userName, String email, boolean emailVerified, boolean enabled, String createdAt, Map<String, String> attributes, String roles) {
        this.id = id;
        this.firstName = firstName;
        this.lastName = lastName;
        this.userName = userName;
        this.email = email;
        this.emailVerified = emailVerified;
        this.enabled = enabled;
        this.createdAt = createdAt;
        this.attributes = attributes;
        this.roles = roles;
    }

    public Map<String, String> getAttributes() {
        return attributes;
    }

    public void setAttributes(Map<String, String> attributes) {
        this.attributes = attributes;
    }

    public String getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(String createdAt) {
        this.createdAt = createdAt;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public boolean isEmailVerified() {
        return emailVerified;
    }

    public void setEmailVerified(boolean emailVerified) {
        this.emailVerified = emailVerified;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public String getFirstName() {
        return firstName;
    }

    public void setFirstName(String firstName) {
        this.firstName = firstName;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getLastName() {
        return lastName;
    }

    public void setLastName(String lastName) {
        this.lastName = lastName;
    }

    public String getRoles() {
        return roles;
    }

    public void setRoles(String roles) {
        this.roles = roles;
    }

    public String getUserName() {
        return userName;
    }

    public void setUserName(String userName) {
        this.userName = userName;
    }
}
