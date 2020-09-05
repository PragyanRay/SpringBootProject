package com.dinuth.keycloakspringbootmicroservice.controller;

import java.util.Arrays;
import java.util.Map;

import javax.annotation.security.RolesAllowed;

import org.jboss.resteasy.client.jaxrs.ResteasyClientBuilder;
import org.json.simple.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

import com.dinuth.keycloakspringbootmicroservice.UserDTO;

import org.keycloak.admin.client.resource.UsersResource;
import javax.ws.rs.core.Response;

import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.UserRepresentation;

@RestController
@RequestMapping("/test")
public class TestController {

	private static final Logger LOGGER=LoggerFactory.getLogger(TestController.class);
	@Autowired
	
	 private Environment env;
	@Value("${keycloak.auth-server-url}")
	private String AUTHURL;
	
	@Value("${keycloak.realm}")
	private String REALM;
	
    @RequestMapping(value = "/anonymous", method = RequestMethod.GET)
    public ResponseEntity<String> getAnonymous() {
        return ResponseEntity.ok("Hello Anonymous");
    }

    @RolesAllowed("user")
    @RequestMapping(value = "/user", method = RequestMethod.GET)
    public ResponseEntity<String> getUser(@RequestHeader String Authorization) {
    	return ResponseEntity.ok("Hello User");
    }

    @RolesAllowed("admin")
    @RequestMapping(value = "/admin", method = RequestMethod.GET)
    public ResponseEntity<String> getAdmin(@RequestHeader String Authorization) {
        return ResponseEntity.ok("Hello Admin");
    }

    @RolesAllowed({ "admin", "user" })
    @RequestMapping(value = "/all-user", method = RequestMethod.GET)
    public ResponseEntity<String> getAllUser(@RequestHeader String Authorization) {
        return ResponseEntity.ok("Hello All User");
    }
    
    @RequestMapping(value = "/create", method = RequestMethod.POST)
	public ResponseEntity<?> createUser(@RequestBody UserDTO userDTO) {
		try {
			LOGGER.info("In create");
			createUserInKeyCloak(userDTO);
			
			return new ResponseEntity<>(HttpStatus.OK);
		}

		catch (Exception ex) {

			ex.printStackTrace();
			return new ResponseEntity<>(HttpStatus.BAD_REQUEST);

		}

	}

   
    @RequestMapping(value = "/accessToken", method = RequestMethod.POST , consumes = {MediaType.APPLICATION_FORM_URLENCODED_VALUE})
    public String getAccessToken(@RequestParam Map<String, String> user) 
    {
    	String baseUrl = env.getProperty("baseUrl");
    	LOGGER.info("baseUrl Value from properties file :: " + baseUrl);
    	String token = null;
	    String access_token = null;
	    RestTemplate restTemplate = new RestTemplate();
	    HttpHeaders headers = new HttpHeaders();
	    headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

	    MultiValueMap<String,String> requestMap = new LinkedMultiValueMap<String,String>();
		requestMap.add("client_id", user.get("client_id"));
		requestMap.add("username", user.get("username"));
		requestMap.add("password", user.get("password"));
		requestMap.add("grant_type", user.get("grant_type"));
		requestMap.add("client_secret", user.get("client_secret"));

	    HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(requestMap, headers);
	    ResponseEntity<Object> response = restTemplate.postForEntity(baseUrl, request, Object.class);
	    LOGGER.info(response.getStatusCode().toString());
	    LOGGER.info(response.getBody().toString());
	    token = response.getBody().toString();
	    LOGGER.info("token from response in string ::: " + token);
	    JSONObject jsonObject = new JSONObject((Map) response.getBody());
	    access_token = jsonObject.get("access_token").toString();
	    LOGGER.info("Access Token from json is ::::: "+  access_token);
	    return access_token;
    }
    
    
    
    public int createUserInKeyCloak(UserDTO userDTO) {

		int statusId = 0;
		try {
			LOGGER.info("In try");
			UsersResource userRessource = getKeycloakUserResource();

			UserRepresentation user = new UserRepresentation();
			user.setUsername(userDTO.getUserName());
			user.setEmail(userDTO.getEmailAddress());
			user.setFirstName(userDTO.getFirstName());
			user.setLastName(userDTO.getLastName());
			user.setEnabled(true);

			// Create user
			Response result = userRessource.create(user);
			LOGGER.info("Keycloak create user response code>>>>" + result.getStatus());

			statusId = result.getStatus();

			if (statusId == 201) {

				String userId = result.getLocation().getPath().replaceAll(".*/([^/]+)$", "$1");

				System.out.println("User created with userId:" + userId);

				// Define password credential
				CredentialRepresentation passwordCred = new CredentialRepresentation();
				passwordCred.setTemporary(false);
				passwordCred.setType(CredentialRepresentation.PASSWORD);
				passwordCred.setValue(userDTO.getPassword());

				// Set password credential
				userRessource.get(userId).resetPassword(passwordCred);

				// set role
				RealmResource realmResource = getRealmResource();
				RoleRepresentation savedRoleRepresentation = realmResource.roles().get("app-user").toRepresentation();
				realmResource.users().get(userId).roles().realmLevel().add(Arrays.asList(savedRoleRepresentation));

				LOGGER.info("Username==" + userDTO.getUserName() + " created in keycloak successfully");

			}

			else if (statusId == 409) {
				LOGGER.info("Username==" + userDTO.getUserName() + " already present in keycloak");

			} else {
				LOGGER.info("Username==" + userDTO.getUserName() + " could not be created in keycloak");

			}

		} catch (Exception e) {
			e.printStackTrace();

		}

		return statusId;

    }
    private UsersResource getKeycloakUserResource() {
    	LOGGER.info("In getKeycloakUserResource");

		Keycloak kc = KeycloakBuilder.builder().serverUrl(AUTHURL).realm("master").username("admin").password("admin")
				.clientId("admin-cli").clientSecret("2b73d87e-2801-4040-9f23-79896e55677f").resteasyClient(new ResteasyClientBuilder().connectionPoolSize(10).build())
				.build();
		
		RealmResource realmResource = kc.realm(REALM);
		UsersResource userRessource = realmResource.users();
		

		return userRessource;
	}
    private RealmResource getRealmResource() {

		Keycloak kc = KeycloakBuilder.builder().serverUrl(AUTHURL).realm("master").username("admin").password("admin")
				.clientId("admin-cli").clientSecret("2b73d87e-2801-4040-9f23-79896e55677f").resteasyClient(new ResteasyClientBuilder().connectionPoolSize(10).build())
				.build();

		RealmResource realmResource = kc.realm(REALM);

		return realmResource;

	}
}