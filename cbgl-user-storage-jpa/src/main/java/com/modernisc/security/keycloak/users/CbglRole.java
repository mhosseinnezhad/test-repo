package com.modernisc.security.keycloak.users;

import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleContainerModel;
import org.keycloak.models.RoleModel;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

public class CbglRole implements RoleModel {

    private String name;
    private String description;
    private String id;
    private RealmModel realm;
    private String containerId;
    private Boolean isClientRole;

    public CbglRole(String name, String description, String id, RealmModel realm, Boolean isClientRole) {
        this.name = name;
        this.description = description;
        this.id = id;
        this.realm = realm;
        this.isClientRole = isClientRole;
        this.containerId = isClientRole ? null : realm.getId();
    }

    public void setId(String id) {
        this.id = id;
    }

    public RealmModel getRealm() {
        return realm;
    }

    public void setRealm(RealmModel realm) {
        this.realm = realm;
    }

    public Boolean getClientRole() {
        return isClientRole;
    }

    public void setClientRole(Boolean clientRole) {
        isClientRole = clientRole;
    }

    public CbglRole() {
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public String getDescription() {
        return description;
    }

    @Override
    public void setDescription(String s) {
        this.description = s;
    }

    @Override
    public String getId() {
        return id;
    }

    @Override
    public void setName(String s) {
        this.name = s;
    }


    @Override
    public boolean isComposite() {
        return false;
    }

    @Override
    public void addCompositeRole(RoleModel roleModel) {

    }

    @Override
    public void removeCompositeRole(RoleModel roleModel) {

    }


    @Override
    public Stream<RoleModel> getCompositesStream() {
        return Stream.empty();
    }

    @Override
    public Stream<RoleModel> getCompositesStream(String s, Integer integer, Integer integer1) {

        return Stream.empty();
    }

    @Override
    public boolean isClientRole() {
        return isClientRole;
    }

    @Override
    public String getContainerId() {
        return containerId;
    }

    @Override
    public RoleContainerModel getContainer() {
        return this.realm;
    }

    @Override
    public boolean hasRole(RoleModel role) {
        return this.id.equals(role.getId()) ||
                this.name.equalsIgnoreCase(role.getName());
    }

    // Attribute methods - empty implementation
    @Override
    public void setSingleAttribute(String name, String value) {
    }

    @Override
    public void setAttribute(String name, List<String> values) {
    }

    @Override
    public void removeAttribute(String name) {
    }

    @Override
    public String getFirstAttribute(String name) {
        return null;
    }

    @Override
    public Stream<String> getAttributeStream(String name) {
        return Stream.empty();
    }

    @Override
    public Map<String, List<String>> getAttributes() {
        return Collections.emptyMap();
    }
}
