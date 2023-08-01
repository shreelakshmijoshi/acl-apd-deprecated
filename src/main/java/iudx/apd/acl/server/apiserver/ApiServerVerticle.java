package iudx.apd.acl.server.apiserver;

import static iudx.apd.acl.server.apiserver.response.ResponseUtil.generateResponse;
import static iudx.apd.acl.server.apiserver.util.Constants.*;
import static iudx.apd.acl.server.apiserver.util.Util.errorResponse;
import static iudx.apd.acl.server.common.HttpStatusCode.BAD_REQUEST;
import static iudx.apd.acl.server.common.Constants.*;

import io.vertx.core.AbstractVerticle;
import io.vertx.core.http.HttpServer;
import io.vertx.core.http.HttpServerOptions;
import io.vertx.core.http.HttpServerResponse;
import io.vertx.core.json.DecodeException;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.Route;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;
import io.vertx.ext.web.handler.BodyHandler;
import io.vertx.ext.web.handler.CorsHandler;
import io.vertx.ext.web.handler.TimeoutHandler;
import io.vertx.ext.web.openapi.RouterBuilder;
import io.vertx.ext.web.openapi.RouterBuilderOptions;
import iudx.apd.acl.server.apiserver.util.RequestType;
import iudx.apd.acl.server.apiserver.util.User;
import iudx.apd.acl.server.authentication.AuthHandler;
import iudx.apd.acl.server.authentication.SomeAuth;
import iudx.apd.acl.server.common.Api;
import iudx.apd.acl.server.common.HttpStatusCode;
import iudx.apd.acl.server.common.ResponseUrn;
import iudx.apd.acl.server.policy.PolicyService;
import iudx.apd.acl.server.validation.FailureHandler;

import java.util.stream.Stream;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * The ACL-APD Server API Verticle.
 *
 * <h1>ACL-APD Server API Verticle</h1>
 *
 * <p>The API Server verticle implements the IUDX ACL-APD Server APIs. It handles the API requests
 * from the clients and interacts with the associated Service to respond.
 *
 * @see io.vertx.core.Vertx
 * @see AbstractVerticle
 * @see HttpServer
 * @see Router
 * @see io.vertx.servicediscovery.ServiceDiscovery
 * @see io.vertx.servicediscovery.types.EventBusService
 * @see io.vertx.spi.cluster.hazelcast.HazelcastClusterManager
 * @version 1.0
 * @since 2020-05-31
 */
public class ApiServerVerticle extends AbstractVerticle {

    private static final Logger LOGGER = LogManager.getLogger(ApiServerVerticle.class);

    private HttpServer server;
    private Router router;
    private int port;
    private boolean isSsl;
    private String dxApiBasePath;
    private Api api;
    private PolicyService policyService;
    private String detail;

    private static User getConsumer() {
        JsonObject consumer =
                new JsonObject()
                        .put("userId", "e5d3ef22-5b25-4d61-aa85-6b3f47ce7121")
                        .put("firstName", "Test")
                        .put("lastName", "User 1")
                        .put("emailId", "test_user_1@example.com")
                        .put("userRole", "consumer");
        return new User(consumer);
    }

    private static User getProvider() {
        JsonObject provider =
                new JsonObject()
                        .put("userId", "4e563a5f-35f0-4f32-92be-8830775a1c5e")
                        .put("firstName", "Test")
                        .put("lastName", "Provider")
                        .put("emailId", "testprovider@example.com")
                        .put("userRole", "provider");
        return new User(provider);
    }

    /**
     * This method is used to start the Verticle. It deploys a verticle in a cluster, reads the
     * configuration, obtains a proxy for the Event bus services exposed through service discovery,
     * start an HTTPs server at port 8443 or an HTTP server at port 8080.
     *
     * @throws Exception which is a startup exception TODO Need to add documentation for all the
     */
    @Override
    public void start() throws Exception {

        /* Define the APIs, methods, endpoints and associated methods. */
        dxApiBasePath = config().getString("dxApiBasePath");
        api = Api.getInstance(dxApiBasePath);

        FailureHandler failureHandler = new FailureHandler();
        /* Initialize service proxy */
        policyService = PolicyService.createProxy(vertx, POLICY_SERVICE_ADDRESS);


        /* Initialize Router builder */
        RouterBuilder.create(vertx, "docs/openapi.yaml")
                .onSuccess(
                        routerBuilder -> {
                            routerBuilder.securityHandler("authorization", new SomeAuth());

                            routerBuilder
                                    .operation(CREATE_POLICY_API)
//                                    .handler(AuthHandler.create(vertx,api))
                                    .handler(this::postPoliciesHandler)
                                    .failureHandler(failureHandler);

                            routerBuilder
                                    .operation(GET_POLICY_API)
                                    .handler(this::getPoliciesHandler)
                                    .failureHandler(failureHandler);

                            routerBuilder
                                    .operation(DELETE_POLICY_API)
                                    .handler(this::deletePoliciesHandler)
                                    .failureHandler(failureHandler);

                            routerBuilder
                                    .operation(CREATE_NOTIFICATIONS_API)
                                    .handler(this::postAccessRequestHandler)
                                    .failureHandler(failureHandler);

                            routerBuilder
                                    .operation(UPDATE_NOTIFICATIONS_API)
                                    .handler(this::putAccessRequestHandler)
                                    .failureHandler(failureHandler);

                            routerBuilder
                                    .operation(GET_NOTIFICATIONS_API)
                                    .handler(this::getAccessRequestHandler)
                                    .failureHandler(failureHandler);

                            routerBuilder
                                    .operation(DELETE_NOTIFICATIONS_API)
                                    .handler(this::deleteAccessRequestHandler)
                                    .failureHandler(failureHandler);

                            routerBuilder.rootHandler(TimeoutHandler.create(1000000, 408));
                            router = routerBuilder.createRouter();
                            configureCorsHandler(routerBuilder);
                            putCommonResponseHeaders();
                            configureErrorHandlers(router);
                            routerBuilder.rootHandler(BodyHandler.create());



                            /* Documentation routes */
                            /* Static Resource Handler */
                            /* Get openapiv3 spec */
                            router
                                    .get(ROUTE_STATIC_SPEC)
                                    .produces(APPLICATION_JSON)
                                    .handler(
                                            routingContext -> {
                                                HttpServerResponse response = routingContext.response();
                                                response.sendFile("docs/openapi.yaml");
                                            });
                            /* Get redoc */
                            router
                                    .get(ROUTE_DOC)
                                    .produces(MIME_TEXT_HTML)
                                    .handler(
                                            routingContext -> {
                                                HttpServerResponse response = routingContext.response();
                                                response.sendFile("docs/apidoc.html");
                                            });

                            /* Read ssl configuration. */
                            HttpServerOptions serverOptions = new HttpServerOptions();
                            setServerOptions(serverOptions);
                            serverOptions.setCompressionSupported(true).setCompressionLevel(5);
                            server = vertx.createHttpServer(serverOptions);
                            server.requestHandler(router).listen(port);

                            printDeployedEndpoints(router);
                            /* Print the deployed endpoints */
                            LOGGER.info("API server deployed on: " + port);
                        })
                .onFailure(
                        failure -> {
                            failure.printStackTrace();
                            LOGGER.error(
                                    "Failed to initialize router builder {}", failure.getCause().getMessage());
                        });
    }

    private void printDeployedEndpoints(Router router) {
        for (Route route : router.getRoutes()) {
            if (route.getPath() != null) {
                LOGGER.info("API Endpoints deployed : " + route.methods() + " : " + route.getPath());
            }
        }
    }
   /* @Override
    public void start() throws Exception {

        *//* Define the APIs, methods, endpoints and associated methods. *//*
        dxApiBasePath = config().getString("dxApiBasePath");
        api = Api.getInstance(dxApiBasePath);

        policyService = PolicyService.createProxy(vertx, POLICY_SERVICE_ADDRESS);
        authenticationService = AuthenticationService.createProxy(vertx, AUTH_SERVICE_ADDRESS);

        router = Router.router(vertx);
        configureCorsHandler(router);

        putCommonResponseHeaders();

        // attach custom http error responses to router
        configureErrorHandlers(router);

        router.route().handler(BodyHandler.create());
        router.route().handler(TimeoutHandler.create(10000, 408));

        *//* Api endpoints *//*
        ValidationHandler policyHandler =
                new ValidationHandler(vertx, RequestType.POLICY, new ValidationHandlerFactory());
        FailureHandler policyFailureHandler = new FailureHandler();
        router.get(api.getPoliciesUrl()).handler(this::getPoliciesHandler);
        router
                .delete(api.getPoliciesUrl())
                .handler(policyHandler)
                .handler(this::deletePoliciesHandler)
                .handler(policyFailureHandler);
        router.post(api.getPoliciesUrl()).handler(this::postPoliciesHandler);

        router.get(api.getRequestPoliciesUrl()).handler(this::getAccessRequestHandler);
        router.delete(api.getRequestPoliciesUrl()).handler(this::deleteAccessRequestHandler);
        router.post(api.getRequestPoliciesUrl()).handler(this::postAccessRequestHandler);
        router.put(api.getRequestPoliciesUrl()).handler(this::putAccessRequestHandler);

        *//* Documentation routes *//*
        *//* Static Resource Handler *//*
        *//* Get openapiv3 spec *//*
        router
                .get(ROUTE_STATIC_SPEC)
                .produces(APPLICATION_JSON)
                .handler(
                        routingContext -> {
                            HttpServerResponse response = routingContext.response();
                            response.sendFile("docs/openapi.yaml");
                        });
        *//* Get redoc *//*
        router
                .get(ROUTE_DOC)
                .produces(MIME_TEXT_HTML)
                .handler(
                        routingContext -> {
                            HttpServerResponse response = routingContext.response();
                            response.sendFile("docs/apidoc.html");
                        });
        *//* Read ssl configuration. *//*
        HttpServerOptions serverOptions = new HttpServerOptions();
        setServerOptions(serverOptions);
        serverOptions.setCompressionSupported(true).setCompressionLevel(5);
        server = vertx.createHttpServer(serverOptions);
        server.requestHandler(router).listen(port);

        *//* Print the deployed endpoints *//*
        LOGGER.info("API server deployed on: " + port);
    }*/

    private void putAccessRequestHandler(RoutingContext routingContext) {}

    private void postAccessRequestHandler(RoutingContext routingContext) {}

    private void deleteAccessRequestHandler(RoutingContext routingContext) {}

    private void getAccessRequestHandler(RoutingContext routingContext) {}

    private void postPoliciesHandler(RoutingContext routingContext) {
        JsonObject requestBody = routingContext.body().asJsonObject();
        // TODO: to add user object in the requestBody before calling createPolicy method
        policyService
                .createPolicy(requestBody,getProvider())
                .onComplete(
                        handler -> {
                            if (handler.succeeded()) {
                                LOGGER.info("Policy created successfully ");
                                handleSuccessResponse(
                                        routingContext, HttpStatusCode.SUCCESS.getValue(), handler.result().toString());
                            } else {
                                LOGGER.error("Policy could not be created");
                                handleFailureResponse(routingContext, handler.cause().getMessage());
                            }
                        });
    }


    private void deletePoliciesHandler(RoutingContext routingContext) {
        JsonObject bodyAsJsonObject = routingContext.body().asJsonObject();
        JsonArray policyList = bodyAsJsonObject.getJsonArray("request");

        User provider = getProvider();
        policyService
                .deletePolicy(policyList, provider)
                .onComplete(
                        handler -> {
                            if (handler.succeeded()) {
                                LOGGER.info("Delete policy succeeded : {} ", handler.result().encode());
                                JsonObject response =
                                        new JsonObject()
                                                .put(TYPE, handler.result().getString(TYPE))
                                                .put(TITLE, handler.result().getString(TITLE))
                                                .put(RESULT, handler.result().getValue(RESULT));
                                handleSuccessResponse(
                                        routingContext, handler.result().getInteger(STATUS_CODE), response.toString());
                            } else {
                                LOGGER.error("Delete policy failed : {} ", handler.cause().getMessage());
                                handleFailureResponse(routingContext, handler.cause().getMessage());
                            }
                        });
    }

    private void getPoliciesHandler(RoutingContext routingContext) {

        User consumer = getConsumer();
        User provider = getProvider();
        policyService
                .getPolicy(provider)
                .onComplete(
                        handler -> {
                            if (handler.succeeded()) {
                                handleSuccessResponse(
                                        routingContext,
                                        handler.result().getInteger(STATUS_CODE),
                                        handler.result().getString(RESULT));
                            } else {
                                handleFailureResponse(routingContext, handler.cause().getMessage());
                            }
                        });
    }

    /**
     * Configures the CORS handler on the provided router.
     *
     * @param routerBuilder The router builder instance to configure the CORS handler on.
     */
/*    private void configureCorsHandler(Router router) {
        router
                .route()
                .handler(
                        CorsHandler.create("*")
                                .allowedHeaders(ALLOWED_HEADERS)
                                .allowedMethods(ALLOWED_METHODS));
    }*/
    private void configureCorsHandler(RouterBuilder routerBuilder) {
        routerBuilder.rootHandler(CorsHandler.create("*")
                        .allowedHeaders(ALLOWED_HEADERS)
                        .allowedMethods(ALLOWED_METHODS));
    }

    /**
     * Configures error handlers for the specified status codes on the provided router.
     *
     * @param router The router instance to configure the error handlers on.
     */
    private void configureErrorHandlers(Router router) {
        HttpStatusCode[] statusCodes = HttpStatusCode.values();
        Stream.of(statusCodes)
                .forEach(
                        code -> {
                            router.errorHandler(
                                    code.getValue(),
                                    errorHandler -> {
                                        HttpServerResponse response = errorHandler.response();
                                        if (response.headWritten()) {
                                            try {
                                                response.close();
                                            } catch (RuntimeException e) {
                                                LOGGER.error("Error: " + e);
                                            }
                                            return;
                                        }
                                        response
                                                .putHeader(CONTENT_TYPE, APPLICATION_JSON)
                                                .setStatusCode(code.getValue())
                                                .end(errorResponse(code));
                                    });
                        });
    }

    /** Sets common response headers to be included in HTTP responses. */
    private void putCommonResponseHeaders() {
        router
                .route()
                .handler(
                        requestHandler -> {
                            requestHandler
                                    .response()
                                    .putHeader("Cache-Control", "no-cache, no-store,  must-revalidate,max-age=0")
                                    .putHeader("Pragma", "no-cache")
                                    .putHeader("Expires", "0")
                                    .putHeader("X-Content-Type-Options", "nosniff");
                            requestHandler.next();
                        });
    }

    /**
     * Sets the server options based on the configuration settings. If SSL is enabled, starts an HTTPS
     * server with the specified HTTP port. If SSL is disabled, starts an HTTP server with the
     * specified HTTP port. If the HTTP port is not specified in the configuration, default ports
     * (8080 for HTTP and 8443 for HTTPS) will be used.
     *
     * @param serverOptions The server options to be configured.
     */
    private void setServerOptions(HttpServerOptions serverOptions) {
        isSsl = config().getBoolean("ssl");
        if (isSsl) {
            LOGGER.debug("Info: Starting HTTPs server");
            port = config().getInteger("httpPort") == null ? 8443 : config().getInteger("httpPort");
        } else {
            LOGGER.debug("Info: Starting HTTP server");
            serverOptions.setSsl(false);
            port = config().getInteger("httpPort") == null ? 8080 : config().getInteger("httpPort");
        }
    }

    /**
     * Handles HTTP Success response from the server
     *
     * @param routingContext Routing context object
     * @param statusCode statusCode to respond with
     * @param result respective result returned from the service
     */
    private void handleSuccessResponse(RoutingContext routingContext, int statusCode, String result) {
        HttpServerResponse response = routingContext.response();
        response.putHeader(CONTENT_TYPE, APPLICATION_JSON).setStatusCode(statusCode).end(result);
    }

    /**
     * Handles Failed HTTP Response
     *
     * @param routingContext Routing context object
     * @param failureMessage Failure message for response
     */
    private void handleFailureResponse(RoutingContext routingContext, String failureMessage) {
        HttpServerResponse response = routingContext.response();
        LOGGER.debug("Failure Message : {} ", failureMessage);

        try {
            JsonObject jsonObject = new JsonObject(failureMessage);
            int type = jsonObject.getInteger(TYPE);
            String title = jsonObject.getString(TITLE);

            HttpStatusCode status = HttpStatusCode.getByValue(type);

            ResponseUrn urn;

            // get the urn by either type or title
            if (title != null) {
                urn = ResponseUrn.fromCode(title);
            } else {

                urn = ResponseUrn.fromCode(String.valueOf(type));
            }
            if (jsonObject.getString(DETAIL) != null) {
                detail = jsonObject.getString(DETAIL);
                response
                        .putHeader(CONTENT_TYPE, APPLICATION_JSON)
                        .setStatusCode(type)
                        .end(generateResponse(status, urn, detail).toString());
            } else {
                response
                        .putHeader(CONTENT_TYPE, APPLICATION_JSON)
                        .setStatusCode(type)
                        .end(generateResponse(status, urn).toString());
            }

        } catch (DecodeException exception) {
            LOGGER.error("Error : Expecting JSON from backend service [ jsonFormattingException ] ");
            handleResponse(response, BAD_REQUEST, ResponseUrn.BACKING_SERVICE_FORMAT_URN);
        }
    }

    private void handleResponse(
            HttpServerResponse response, HttpStatusCode statusCode, ResponseUrn urn) {
        handleResponse(response, statusCode, urn, statusCode.getDescription());
    }

    private void handleResponse(
            HttpServerResponse response,
            HttpStatusCode statusCode,
            ResponseUrn urn,
            String failureMessage) {
        response
                .putHeader(CONTENT_TYPE, APPLICATION_JSON)
                .setStatusCode(statusCode.getValue())
                .end(generateResponse(statusCode, urn, failureMessage).toString());
    }

}
