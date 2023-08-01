package iudx.apd.acl.server.authentication;

import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import io.vertx.ext.web.RoutingContext;
import iudx.apd.acl.server.common.Api;

import static iudx.apd.acl.server.common.Constants.AUTH_SERVICE_ADDRESS;

public class AuthHandler implements Handler<RoutingContext> {
    static AuthenticationService authenticator;
    private static Api api;
    public static AuthHandler create(Vertx vertx, Api apis) {
        authenticator = AuthenticationService.createProxy(vertx, AUTH_SERVICE_ADDRESS);
        api = apis;
        return new AuthHandler();
    }
    @Override
    public void handle(RoutingContext routingContext) {

    }
}
