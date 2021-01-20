package org.acme;

import io.quarkus.test.common.QuarkusTestResource;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.RestAssured;
import io.restassured.http.ContentType;
import org.acme.resources.KeycloakServerContainer;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.junit.jupiter.api.Test;
import org.keycloak.representations.AccessTokenResponse;

import static io.restassured.RestAssured.given;
import static org.hamcrest.CoreMatchers.is;

@QuarkusTest
@QuarkusTestResource(KeycloakServerContainer.class)
public class GreetingResourceTest {

    @Test
    public void testHelloEndpoint() {
        given()
                .auth()
                .oauth2(getAccessToken("test-user"))
                .when().get("/hello-resteasy")
                .then()
                .statusCode(200)
                .body(is("Hello test-user: MyCustomAttribute"));
    }

    @Test
    public void testHelloEndpoint2() {
        given()
                .auth()
                .oauth2(getAccessToken("test-user"))
                .contentType(ContentType.JSON)
                .post("/hello-resteasy/test")
                .then()
                .statusCode(200)
                .body(is("Hello test-user: MyCustomAttribute"));
    }

    private String getAccessToken(String userName) {
        return RestAssured.given()
                .param("grant_type", "password")
                .param("username", userName)
                .param("password", userName)
                .param("client_id", clientId)
                .param("client_secret", clientSecret)
                .when()
                .post(keycloakServerUrl + "/realms/test-realm/protocol/openid-connect/token")
                .as(AccessTokenResponse.class).getToken();
    }

    @ConfigProperty(name = "quarkus.oidc.credentials.secret")
    String clientSecret;

    @ConfigProperty(name = "quarkus.oidc.client-id")
    String clientId;

    @ConfigProperty(name = "keycloak-test.server-url")
    String keycloakServerUrl;

}