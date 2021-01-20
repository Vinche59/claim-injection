package org.acme.resources;

import io.quarkus.test.common.QuarkusTestResourceLifecycleManager;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.ProtocolMapperRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.RolesRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.representations.idm.authorization.DecisionStrategy;
import org.keycloak.representations.idm.authorization.Logic;
import org.keycloak.representations.idm.authorization.PolicyRepresentation;
import org.keycloak.representations.idm.authorization.ResourceRepresentation;
import org.keycloak.representations.idm.authorization.ResourceServerRepresentation;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;

import java.text.MessageFormat;
import java.time.Duration;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class KeycloakServerContainer implements QuarkusTestResourceLifecycleManager {
    protected static final String DOCKER_IMAGE = "jboss/keycloak:11.0.3";
    protected static final String ADMIN_USER = "admin";
    protected static final String ADMIN_PASSWORD = "admin";
    private static final String REALM = "test-realm";
    private static final String CLIENT_ID = "test-client";
    private static final String CLIENT_SECRET = "test-secret";

    private GenericContainer<?> container;

    @Override
    public Map<String, String> start() {
        container = new GenericContainer<>(DOCKER_IMAGE)
                .withExposedPorts(8080)
                .withEnv("KEYCLOAK_USER", ADMIN_USER)
                .withEnv("KEYCLOAK_PASSWORD", ADMIN_PASSWORD)
                .waitingFor(Wait
                        .forHttp("/auth/")
                        .forStatusCode(200)
                        .withStartupTimeout(Duration.of(180, ChronoUnit.SECONDS)));

        container.start();

        String serverUrl = "http://127.0.0.1:" + container.getMappedPort(8080) + "/auth";

        Keycloak keycloakClient = KeycloakBuilder.builder()
                .serverUrl(serverUrl)
                .realm("master")
                .clientId("admin-cli")
                .username(ADMIN_USER)
                .password(ADMIN_PASSWORD)
                .build();

        keycloakClient.realms().create(setupKeycloakServer(REALM));
        keycloakClient.close();

        Map<String, String> overrides = new HashMap<>();
        overrides.put("quarkus.oidc.auth-server-url", serverUrl + "/realms/" + REALM);
        overrides.put("quarkus.oidc.credentials.secret", CLIENT_SECRET);
        overrides.put("quarkus.oidc.client-id", CLIENT_ID);
        overrides.put("keycloak-test.server-url", serverUrl);

        return overrides;
    }

    @Override
    public void stop() {
        if (container != null)
            container.stop();
    }

    private RealmRepresentation setupKeycloakServer(String realmName) {
        RealmRepresentation realmRepresentation = createRealm(realmName);

        realmRepresentation.getClients().add(createClient(CLIENT_ID, CLIENT_SECRET));
        realmRepresentation.getRoles().getRealm().add(createRole("TestRole"));
        realmRepresentation.getUsers().add(createUser("test-user", createAttributes(), "TestRole"));

        return realmRepresentation;
    }

    private RealmRepresentation createRealm(String name) {
        RealmRepresentation realm = new RealmRepresentation();

        realm.setId(name);
        realm.setRealm(name);
        realm.setEnabled(true);
        realm.setUsers(new ArrayList<>());
        realm.setClients(new ArrayList<>());
        realm.setGroups(new ArrayList<>());

        RolesRepresentation roles = new RolesRepresentation();
        List<RoleRepresentation> realmRoles = new ArrayList<>();

        roles.setRealm(realmRoles);
        realm.setRoles(roles);

        return realm;
    }

    private RoleRepresentation createRole(String name) {
        RoleRepresentation role = new RoleRepresentation(name, null, false);
        role.setId(name);

        return role;
    }

    private ClientRepresentation createClient(String clientId, String clientSecret) {
        ClientRepresentation client = new ClientRepresentation();

        client.setClientId(clientId);
        client.setSecret(clientSecret);
        client.setPublicClient(false);
        client.setProtocol("openid-connect");
        client.setStandardFlowEnabled(false);
        client.setDirectAccessGrantsEnabled(true);
        client.setAuthorizationServicesEnabled(true);
        client.setServiceAccountsEnabled(true);
        client.setEnabled(true);

        client.setProtocolMappers(new ArrayList<>());
        client.getProtocolMappers().add(createUserAttributeMapper("customAttribute", "String"));

        ResourceServerRepresentation authorizationSettings = new ResourceServerRepresentation();

        authorizationSettings.setResources(new ArrayList<>());
        authorizationSettings.setPolicies(new ArrayList<>());

        client.setAuthorizationSettings(authorizationSettings);

        configureTestRolePermission(client.getAuthorizationSettings());

        return client;
    }

    private void configureTestRolePermission(ResourceServerRepresentation settings) {
        PolicyRepresentation policy = createResourcePolicy("Only TestRole", "TestRole", settings);
        createPermission(settings, createResource(settings, "TestRole", new HashSet<>(Collections.singletonList(
                "/*"))), policy);
    }

    private void createPermission(ResourceServerRepresentation settings, ResourceRepresentation resource,
                                    PolicyRepresentation policy) {
        PolicyRepresentation permission = new PolicyRepresentation();

        permission.setName(resource.getName() + " Permission");
        permission.setType("resource");
        permission.setResources(new HashSet<>());
        permission.getResources().add(resource.getName());
        permission.setPolicies(new HashSet<>());
        permission.getPolicies().add(policy.getName());

        settings.getPolicies().add(permission);
    }

    private ResourceRepresentation createResource(ResourceServerRepresentation authorizationSettings, String name,
                                                    Set<String> uris) {
        ResourceRepresentation resource = new ResourceRepresentation(name);

        if (uris != null)
            resource.setUris(uris);

        authorizationSettings.getResources().add(resource);
        return resource;
    }

    private PolicyRepresentation createResourcePolicy(String name, String roleName, ResourceServerRepresentation settings) {
        PolicyRepresentation policy = new PolicyRepresentation();

        policy.setName(name);
        policy.setType("role");
        policy.setLogic(Logic.POSITIVE);
        policy.setDecisionStrategy(DecisionStrategy.UNANIMOUS);

        policy.setConfig(new HashMap<>());
        policy.getConfig().put("roles", MessageFormat.format("['{'\"id\":\"{0}\",\"required\":true'}']", roleName));

        settings.getPolicies().add(policy);

        return policy;
    }

    private UserRepresentation createUser(String username, Map<String, List<String>> attributes, String... realmRoles) {
        UserRepresentation user = new UserRepresentation();

        user.setId(username);
        user.setUsername(username);
        user.setEnabled(true);
        user.setCredentials(new ArrayList<>());
        user.setRealmRoles(Arrays.asList(realmRoles));
        user.setAttributes(attributes);

        CredentialRepresentation credential = new CredentialRepresentation();

        credential.setType(CredentialRepresentation.PASSWORD);
        credential.setValue(username);
        credential.setTemporary(false);

        user.getCredentials().add(credential);

        return user;
    }

    private Map<String, List<String>> createAttributes() {
        Map<String, List<String>> attributes = new HashMap<>();

        attributes.put("customAttribute", Collections.singletonList("MyCustomAttribute"));

        return attributes;
    }

    private ProtocolMapperRepresentation createUserAttributeMapper(String name, String jsonType) {
        ProtocolMapperRepresentation pmr = new ProtocolMapperRepresentation();

        pmr.setName(name);
        pmr.setProtocol("openid-connect");
        pmr.setProtocolMapper("oidc-usermodel-attribute-mapper");
        pmr.setConfig(new HashMap<>());

        pmr.getConfig().put("id.token.claim", "true");
        pmr.getConfig().put("access.token.claim", "true");
        pmr.getConfig().put("userinfo.token.claim", "true");
        pmr.getConfig().put("user.attribute", name);
        pmr.getConfig().put("claim.name", name);
        pmr.getConfig().put("jsonType.label", jsonType);

        return pmr;
    }


}
