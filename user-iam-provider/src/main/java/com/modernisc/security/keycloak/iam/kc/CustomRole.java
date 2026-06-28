package com.modernisc.security.keycloak.iam.kc;

import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleContainerModel;
import org.keycloak.models.RoleModel;

import java.util.*;
import java.util.stream.Stream;

public class CustomRole implements RoleModel {
    private String name;
    private String description;
    private String id;
    private RealmModel realm;

    public CustomRole(String name, String description, String id, RealmModel realm) {
        this.name = name;
        this.description = description;
        this.id = id;
        this.realm = realm;
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
        return null;
    }

    @Override
    public Stream<RoleModel> getCompositesStream(String s, Integer integer, Integer integer1) {
        return null;
    }

    @Override
    public boolean isClientRole() {
        return false;
    }

    @Override
    public String getContainerId() {
        return this.realm.getId();
    }

    @Override
    public RoleContainerModel getContainer() {
        this.realm.getRolesStream();
        return this.realm;
    }

    @Override
    public boolean hasRole(RoleModel roleModel) {
        return false;
    }

    @Override
    public void setSingleAttribute(String s, String s1) {

    }

    @Override
    public void setAttribute(String s, List<String> list) {

    }

    @Override
    public void removeAttribute(String s) {

    }

    @Override
    public String getFirstAttribute(String s) {
        return "";
    }
    @Override
    public Stream<String> getAttributeStream(String s) {
        return Stream.empty();
    }

    @Override
    public Map<String, List<String>> getAttributes() {
        return Collections.EMPTY_MAP;
    }
}
