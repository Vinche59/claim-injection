package org.acme;

import io.quarkus.security.Authenticated;
import org.eclipse.microprofile.jwt.Claim;
import org.jboss.resteasy.annotations.cache.NoCache;

import javax.enterprise.context.RequestScoped;
import javax.inject.Inject;
import javax.transaction.Transactional;
import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;

@Path("/hello-resteasy")
@RequestScoped
@Authenticated
@NoCache
@Produces({MediaType.APPLICATION_JSON})
@Consumes({MediaType.APPLICATION_JSON})
public class GreetingResource {

    @GET
    public String hello() {
        return "Hello " + userName + ": " + customAttribute;
    }

    @POST
    @Path("test")
    public String test() {
        return "Hello " + userName + ": " + customAttribute;
    }

    @Inject
    @Claim("preferred_username")
    String userName;

    @Inject
    @Claim("customAttribute")
    String customAttribute;
}