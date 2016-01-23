/*
 * Copyright 2014 Google Inc. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.google.identitytoolkit;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.Proxy;
import java.net.URLEncoder;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.logging.Logger;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Optional;
import com.google.common.base.Preconditions;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Lists;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

/**
 * Google Identity Toolkit client library. This class is the only interface that third party
 * developers needs to know to integrate Gitkit with their backend server. Main features are
 * Gitkit token verification and Gitkit remote API wrapper.
 */
public class GitkitClient {

  @VisibleForTesting
  static final String GITKIT_API_BASE =
      "https://www.googleapis.com/identitytoolkit/v3/relyingparty/";

  private static final Logger logger = Logger.getLogger(GitkitClient.class.getName());
  private final JsonTokenHelper tokenHelper;
  private final RpcHelper rpcHelper;
  private final String widgetUrl;
  private final String cookieName;

  /**
   * Constructs a Gitkit client.
   *
   * @param clientId Google oauth2 web application client id. Audience in Gitkit token must match
   *                 this client id.
   * @param serviceAccountEmail Google service account email.
   * @param keyStream Google service account private p12 key stream.
   * @param widgetUrl Url of the Gitkit widget, must starting with /.
   * @param cookieName Gitkit cookie name. Used to extract Gitkit token from incoming http request.
   * @param httpSender Concrete http sender when Gitkit client needs to call Gitkit remote API.
   * @param serverApiKey Server side API key in Google Developer Console.
   */
  public GitkitClient(
      String clientId,
      String serviceAccountEmail,
      InputStream keyStream,
      String widgetUrl,
      String cookieName,
      HttpSender httpSender,
      String serverApiKey) {
    this(clientId, null, serviceAccountEmail, keyStream, widgetUrl, cookieName,
          httpSender, serverApiKey);
  }

  /**
   * Constructs a Gitkit client.
   *
   * @param clientId Google oauth2 web application client id. Audience in Gitkit token must match
   *                 this client id.
   * @param projectId Google developer console project id.
   * @param serviceAccountEmail Google service account email.
   * @param keyStream Google service account private p12 key stream.
   * @param widgetUrl Url of the Gitkit widget, must starting with /.
   * @param cookieName Gitkit cookie name. Used to extract Gitkit token from incoming http request.
   * @param httpSender Concrete http sender when Gitkit client needs to call Gitkit remote API.
   * @param serverApiKey Server side API key in Google Developer Console.
   */
  public GitkitClient(
      String clientId,
      String projectId,
      String serviceAccountEmail,
      InputStream keyStream,
      String widgetUrl,
      String cookieName,
      HttpSender httpSender,
      String serverApiKey) {
    rpcHelper = new RpcHelper(httpSender, GITKIT_API_BASE, serviceAccountEmail, keyStream);
    tokenHelper = new JsonTokenHelper(rpcHelper, serverApiKey, projectId, clientId);
    this.widgetUrl = widgetUrl;
    this.cookieName = cookieName;
  }

  /**
   * Constructs a Gitkit client from a JSON config file
   *
   * @param configPath Path to JSON configuration file
   * @return Gitkit client
   */
  public static GitkitClient createFromJson(String configPath)
      throws GitkitClientException, IOException {
    return createFromJson(configPath, null);
  }

    /**
     * Constructs a Gitkit client from a JSON config file
     *
     * @param configPath Path to JSON configuration file
     * @param proxy the Proxy object to use when using Gitkit client behind a proxy
     * @return Gitkit client
     */
  public static GitkitClient createFromJson(String configPath, Proxy proxy)
      throws GitkitClientException, IOException {
    JsonObject configData =
        new JsonParser().parse(
            StandardCharsets.UTF_8.decode(
                ByteBuffer.wrap(Files.readAllBytes(Paths.get(configPath))))
                .toString()).getAsJsonObject();
    if (!configData.has("clientId") && !configData.has("projectId")) {
      throw new GitkitClientException("Missing projectId or clientId in server configuration.");
    }
    JsonElement clientIdElement = configData.get("clientId");
    JsonElement projectIdElement = configData.get("projectId");
    JsonElement serverApiKeyElement = configData.get("serverApiKey");
    return new GitkitClient.Builder()
         .setProxy(proxy)
         .setGoogleClientId((clientIdElement == null) ? null : clientIdElement.getAsString())
         .setProjectId((projectIdElement == null) ? null : projectIdElement.getAsString())
         .setServiceAccountEmail(configData.get("serviceAccountEmail").getAsString())
         .setKeyStream(new FileInputStream(configData.get("serviceAccountPrivateKeyFile").getAsString()))
         .setWidgetUrl(configData.get("widgetUrl").getAsString())
         .setCookieName(configData.get("cookieName").getAsString())
         .setServerApiKey((serverApiKeyElement == null) ? null : serverApiKeyElement.getAsString())
         .build();
  }

  /**
   * Verifies a Gitkit token.
   *
   * @param token token string to be verified.
   * @return the JSON object for the payload of the token if the token is valid.
   * @throws GitkitClientException if token has invalid signature
   */
  public JsonObject validateTokenToJson(String token) throws GitkitClientException {
    if (token == null) {
      return null;
    }
    try {
      return tokenHelper.verifyAndDeserialize(token).getPayloadAsJsonObject();
    } catch (SignatureException e) {
      throw new GitkitClientException(e);
    }
  }

  /**
   * Verifies a Gitkit token.
   *
   * @param token token string to be verified.
   * @return Gitkit user if token is valid.
   * @throws GitkitClientException if token has invalid signature
   */
  public GitkitUser validateToken(String token) throws GitkitClientException {
    JsonObject jsonToken = validateTokenToJson(token);
    if (jsonToken == null) {
      return null;
    }
    return new GitkitUser()
        .setLocalId(jsonToken.get(JsonTokenHelper.ID_TOKEN_USER_ID).getAsString())
        .setEmail(jsonToken.get(JsonTokenHelper.ID_TOKEN_EMAIL).getAsString())
        .setCurrentProvider(jsonToken.has(JsonTokenHelper.ID_TOKEN_PROVIDER)
            ? jsonToken.get(JsonTokenHelper.ID_TOKEN_PROVIDER).getAsString()
            : null)
        .setName(jsonToken.has(JsonTokenHelper.ID_TOKEN_DISPLAY_NAME)
            ? jsonToken.get(JsonTokenHelper.ID_TOKEN_DISPLAY_NAME).getAsString()
            : null)
        .setPhotoUrl(jsonToken.has(JsonTokenHelper.ID_TOKEN_PHOTO_URL)
            ? jsonToken.get(JsonTokenHelper.ID_TOKEN_PHOTO_URL).getAsString()
            : null);
  }

  /**
   * Verifies Gitkit token in http request.
   *
   * @param request http request
   * @return Gitkit user if valid token is found in the request.
   * @throws GitkitClientException if there is token but signature is invalid
   */
  public GitkitUser validateTokenInRequest(HttpServletRequest request)
      throws GitkitClientException {
    Cookie[] cookies = request.getCookies();
    if (cookieName == null || cookies == null) {
      return null;
    }

    for (Cookie cookie : cookies) {
      if (cookieName.equals(cookie.getName())) {
        return validateToken(cookie.getValue());
      }
    }
    return null;
  }

  /**
   * Verifies the user entered password at Gitkit server.
   *
   * @param email The email of the user
   * @param password The password inputed by the user
   * @param pendingIdToken The GITKit token for the non-trusted IDP, which is to be confirmed by the user
   * @param captchaResponse Response to the captcha
   * @return Gitkit user if password is valid.
   * @throws GitkitClientException for invalid request
   * @throws GitkitServerException for server error
   */
  public GitkitUser verifyPassword(String email, String password, String pendingIdToken, String captchaResponse)
      throws GitkitClientException, GitkitServerException {
    JsonObject result = rpcHelper.verifyPassword(email, password, pendingIdToken, captchaResponse);
    return jsonToUser(result);
  }

  /**
   * Verifies the user entered password at Gitkit server.
   *
   * @param email The email of the user
   * @param password The password inputed by the user
   * @return Gitkit user if password is valid.
   * @throws GitkitClientException for invalid request
   * @throws GitkitServerException for server error
   */
  public GitkitUser verifyPassword(String email, String password)
      throws GitkitClientException, GitkitServerException {
      return verifyPassword(email, password, null, null);
  }

  /**
   * Gets user info from GITkit service using Gitkit token. Can be used to verify a Gitkit token
   * remotely.
   *
   * @param token the gitkit token.
   * @return Gitkit user info if token is valid.
   * @throws GitkitClientException if request is invalid
   * @throws GitkitServerException for Gitkit server error
   */
  public GitkitUser getUserByToken(String token)
      throws GitkitClientException, GitkitServerException {
    GitkitUser gitkitUser = validateToken(token);
    if (gitkitUser == null) {
      throw new GitkitClientException("invalid gitkit token");
    }
    JsonObject result = rpcHelper.getAccountInfo(token);
    JsonObject jsonUser = result.get("users").getAsJsonArray().get(0).getAsJsonObject();
    return jsonToUser(jsonUser)
        // gitkit server does not return current provider
        .setCurrentProvider(gitkitUser.getCurrentProvider());
  }

  /**
   * Gets user info given an email.
   *
   * @param email user email.
   * @return Gitkit user info.
   * @throws GitkitClientException if request is invalid
   * @throws GitkitServerException for Gitkit server error
   */
  public GitkitUser getUserByEmail(String email)
      throws GitkitClientException, GitkitServerException {
    Preconditions.checkNotNull(email);
    JsonObject result = rpcHelper.getAccountInfoByEmail(email);
    return jsonToUser(result.get("users").getAsJsonArray().get(0).getAsJsonObject());
  }

  /**
   * Gets user info given a user id.
   *
   * @param localId user identifier at Gitkit.
   * @return Gitkit user info.
   * @throws GitkitClientException if request is invalid
   * @throws GitkitServerException for Gitkit server error
   */
  public GitkitUser getUserByLocalId(String localId)
      throws GitkitClientException, GitkitServerException {
    Preconditions.checkNotNull(localId);
    JsonObject result = rpcHelper.getAccountInfoById(localId);
    return jsonToUser(result.get("users").getAsJsonArray().get(0).getAsJsonObject());
  }

  /**
   * Gets all user info of this web site. Underlying requests are send with default pagination size.
   *
   * @return lazy iterator over all user accounts.
   */
  public Iterator<GitkitUser> getAllUsers() {
    return getAllUsers(null);
  }

  /**
   * Gets all user info of this web site. Underlying requests are paginated and send on demand with
   * given size.
   *
   * @param resultsPerRequest pagination size
   * @return lazy iterator over all user accounts.
   */
  public Iterator<GitkitUser> getAllUsers(final Integer resultsPerRequest) {
    return new DownloadIterator<GitkitUser>() {

      private String nextPageToken = null;

      @Override
      protected Iterator<GitkitUser> getNextResults() {
        try {
          JsonObject response = rpcHelper.downloadAccount(nextPageToken, resultsPerRequest);
          nextPageToken = response.has("nextPageToken")
              ? response.get("nextPageToken").getAsString()
              : null;
          if (response.has("users")) {
            return jsonToList(response.get("users").getAsJsonArray()).iterator();
          }
        } catch (GitkitServerException e) {
          logger.warning(e.getMessage());
        } catch (GitkitClientException e) {
          logger.warning(e.getMessage());
        }
        return ImmutableSet.<GitkitUser>of().iterator();
      }
    };
  }

  /**
   * Updates a user info at Gitkit server.
   *
   * @param user user info to be updated.
   * @return the updated user info
   * @throws GitkitClientException for invalid request
   * @throws GitkitServerException for server error
   */
  public GitkitUser updateUser(GitkitUser user)
      throws GitkitClientException, GitkitServerException {
    return jsonToUser(rpcHelper.updateAccount(user));
  }

  /**
   * Uploads multiple user accounts to Gitkit server.
   *
   * @param hashAlgorithm hash algorithm. Supported values are HMAC_SHA256, HMAC_SHA1, HMAC_MD5,
   *                      PBKDF_SHA1, MD5 and SCRYPT.
   * @param hashKey key of hash algorithm
   * @param users list of user accounts to be uploaded
   * @throws GitkitClientException for invalid request
   * @throws GitkitServerException for server error
   */
  public void uploadUsers(String hashAlgorithm, byte[] hashKey, List<GitkitUser> users)
      throws GitkitServerException, GitkitClientException {
      uploadUsers(hashAlgorithm, hashKey, users, null, null, null);
  }

  /**
   * Uploads multiple user accounts to Gitkit server.
   *
   * @param hashAlgorithm hash algorithm. Supported values are HMAC_SHA256, HMAC_SHA1, HMAC_MD5,
   *                      PBKDF_SHA1, MD5 and SCRYPT.
   * @param hashKey key of hash algorithm
   * @param users list of user accounts to be uploaded
   * @param saltSeparator the salt separator
   * @param rounds rounds for hash calculation. Used by scrypt and similar algorithms.
   * @param memoryCost memory cost for hash calculation. Used by scrypt similar algorithms.
   * @throws GitkitClientException for invalid request
   * @throws GitkitServerException for server error
   */
  public void uploadUsers(String hashAlgorithm, byte[] hashKey, List<GitkitUser> users,
                          byte[] saltSeparator, Integer rounds, Integer memoryCost)
          throws GitkitServerException, GitkitClientException {
      rpcHelper.uploadAccount(hashAlgorithm, hashKey, users, saltSeparator, rounds, memoryCost);
  }

  /**
   * Deletes a user account at Gitkit server.
   *
   * @param user user to be deleted.
   * @throws GitkitClientException for invalid request
   * @throws GitkitServerException for server error
   */
  public void deleteUser(GitkitUser user) throws GitkitServerException, GitkitClientException {
    deleteUser(user.getLocalId());
  }

  /**
   * Deletes a user account at Gitkit server.
   *
   * @param localId user id to be deleted.
   * @throws GitkitClientException for invalid request
   * @throws GitkitServerException for server error
   */
  public void deleteUser(String localId) throws GitkitServerException, GitkitClientException {
    rpcHelper.deleteAccount(localId);
  }

  /**
   * Gets out-of-band response. Used by oob endpoint for ResetPassword and ChangeEmail operation.
   * The web site needs to send user an email containing the oobUrl in the response. The user needs
   * to click the oobUrl to finish the operation.
   *
   * @param req http request for the oob endpoint
   * @return the oob response.
   * @throws GitkitServerException
   */
  public OobResponse getOobResponse(HttpServletRequest req)
      throws GitkitServerException {
    String gitkitToken = lookupCookie(req, cookieName);
    return getOobResponse(req, gitkitToken);
  }

  /**
   * Gets out-of-band response. Used by oob endpoint for ResetPassword and ChangeEmail operation.
   * The web site needs to send user an email containing the oobUrl in the response. The user needs
   * to click the oobUrl to finish the operation.
   *
   * @param req http request for the oob endpoint
   * @param gitkitToken Gitkit token of authenticated user, required for ChangeEmail operation
   * @return the oob response.
   * @throws GitkitServerException
   */
  public OobResponse getOobResponse(HttpServletRequest req, String gitkitToken)
      throws GitkitServerException {
    try {
      String action = req.getParameter("action");
      if ("resetPassword".equals(action)) {
        String oobLink = buildOobLink(buildPasswordResetRequest(req), action);
        return new OobResponse(
            req.getParameter("email"),
            null,
            oobLink,
            OobAction.RESET_PASSWORD);
      } else if ("changeEmail".equals(action)) {
        if (gitkitToken == null) {
          return new OobResponse("login is required");
        } else {
          String oobLink = buildOobLink(buildChangeEmailRequest(req, gitkitToken), action);
          return new OobResponse(
              req.getParameter("oldEmail"),
              req.getParameter("newEmail"),
              oobLink,
              OobAction.CHANGE_EMAIL);
        }
      } else {
        return new OobResponse("unknown request");
      }
    } catch (GitkitClientException e) {
      return new OobResponse(e.getMessage());
    }
  }

  public String getEmailVerificationLink(String email)
      throws GitkitServerException, GitkitClientException {
    return buildOobLink(buildEmailVerificationRequest(email), "verifyEmail");
  }

  public static Builder newBuilder() {
    return new Builder();
  }

  private String lookupCookie(HttpServletRequest request, String cookieName) {
    Cookie[] cookies = request.getCookies();
    if (cookies == null) {
      return null;
    }
    for (Cookie cookie : cookies) {
      if (cookieName.equals(cookie.getName())) {
        return cookie.getValue();
      }
    }
    return null;
  }

  private String buildOobLink(JsonObject oobReq, String modeParam)
      throws GitkitClientException, GitkitServerException {
    try {
      JsonObject result = rpcHelper.getOobCode(oobReq);
      if (!result.has("oobCode")) {
        throw new GitkitServerException("Result does not have oobCode. Response is "
            + (result != null ? result.toString() : "(null)"));
      }
      String code = result.get("oobCode").getAsString();
      return widgetUrl + "?mode=" + modeParam + "&oobCode="
          + URLEncoder.encode(code, "UTF-8");
    } catch (UnsupportedEncodingException e) {
      // should never happen
      throw new GitkitServerException(e);
    }
  }

  private JsonObject buildPasswordResetRequest(HttpServletRequest req) {
    JsonObject result = new JsonObject();
    result.addProperty("email", req.getParameter("email"));
    result.addProperty("userIp", req.getRemoteAddr());
    result.addProperty("challenge", req.getParameter("challenge"));
    result.addProperty("captchaResp", req.getParameter("response"));
    result.addProperty("requestType", "PASSWORD_RESET");
    return result;
  }

  private JsonObject buildChangeEmailRequest(HttpServletRequest req, String gitkitToken) {
    JsonObject result = new JsonObject();
    result.addProperty("email", req.getParameter("oldEmail"));
    result.addProperty("userIp", req.getRemoteAddr());
    result.addProperty("newEmail", req.getParameter("newEmail"));
    result.addProperty("idToken", gitkitToken);
    result.addProperty("requestType", "NEW_EMAIL_ACCEPT");
    return result;
  }

  private JsonObject buildEmailVerificationRequest(String email) {
    JsonObject result = new JsonObject();
    result.addProperty("email", email);
    result.addProperty("requestType", "VERIFY_EMAIL");
	return result;
  }

  /**
   * Gitkit out-of-band actions.
   */
  public enum OobAction {
    RESET_PASSWORD,
    CHANGE_EMAIL
  }

  /**
   * Wrapper class containing the out-of-band responses.
   */
  public class OobResponse {
    private static final String SUCCESS_RESPONSE = "{\"success\": true}";
    private static final String ERROR_PREFIX = "{\"error\": \"";
    private final String email;
    private final String newEmail;
    private final Optional<String> oobUrl;
    private final OobAction oobAction;
    private final String responseBody;
    private final String recipient;

    public OobResponse(String responseBody) {
      this(null, null, Optional.<String>absent(), null, ERROR_PREFIX + responseBody + "\" }");
    }

    public OobResponse(String email, String newEmail, String oobUrl, OobAction oobAction)
    {
      this(email, newEmail, Optional.of(oobUrl), oobAction, SUCCESS_RESPONSE);
    }

    public OobResponse(String email, String newEmail, Optional<String> oobUrl, OobAction oobAction,
        String responseBody) {
      this.email = email;
      this.newEmail = newEmail;
      this.oobUrl = oobUrl;
      this.oobAction = oobAction;
      this.responseBody = responseBody;
      this.recipient = newEmail == null ? email : newEmail;
    }

    public Optional<String> getOobUrl() {
      return oobUrl;
    }

    public OobAction getOobAction() {
      return oobAction;
    }

    public String getResponseBody() {
      return responseBody;
    }

    public String getEmail() {
      return email;
    }

    public String getNewEmail() {
      return newEmail;
    }

    public String getRecipient() {
      return recipient;
    }
  }

  /**
   * Builder class to construct Gitkit client instance.
   */
  public static class Builder {
    private String clientId;
    private String projectId = null;
    private HttpSender httpSender = new HttpSender();
    private String widgetUrl;
    private String serviceAccountEmail;
    private InputStream keyStream;
    private String serverApiKey;
    private String cookieName = "gtoken";

    public Builder setProxy(Proxy proxy) {
      this.httpSender = new HttpSender(proxy);
      return this;
    }

    public Builder setGoogleClientId(String clientId) {
      this.clientId = clientId;
      return this;
    }

    public Builder setProjectId(String projectId) {
      this.projectId = projectId;
      return this;
    }

    public Builder setWidgetUrl(String url) {
      this.widgetUrl = url;
      return this;
    }

    public Builder setKeyStream(InputStream keyStream) {
      this.keyStream = keyStream;
      return this;
    }

    public Builder setServiceAccountEmail(String serviceAccountEmail) {
      this.serviceAccountEmail = serviceAccountEmail;
      return this;
    }

    public Builder setCookieName(String cookieName) {
      this.cookieName = cookieName;
      return this;
    }

    public Builder setHttpSender(HttpSender httpSender) {
      this.httpSender = httpSender;
      return this;
    }

    public Builder setServerApiKey(String serverApiKey) {
      this.serverApiKey = serverApiKey;
      return this;
    }

    public GitkitClient build() {
      return new GitkitClient(clientId, projectId, serviceAccountEmail, keyStream, widgetUrl, cookieName,
          httpSender, serverApiKey);
    }
  }

  private List<GitkitUser> jsonToList(JsonArray accounts) {
    List<GitkitUser> list = Lists.newLinkedList();
    for (int i = 0; i < accounts.size(); i++) {
      list.add(jsonToUser(accounts.get(i).getAsJsonObject()));
    }
    return list;
  }

  private GitkitUser jsonToUser(JsonObject jsonUser) {
	JsonElement displayNameElement = jsonUser.get("displayName");
	JsonElement photoUrlElement = jsonUser.get("photoUrl");
	JsonElement providerUserInfoElement = jsonUser.get("providerUserInfo");
    GitkitUser user = new GitkitUser()
        .setLocalId(jsonUser.get("localId").getAsString())
        .setEmail(jsonUser.get("email").getAsString())
        .setName((displayNameElement == null) ? "" : displayNameElement.getAsString())
        .setPhotoUrl((photoUrlElement == null) ? "" : photoUrlElement.getAsString())
        .setProviders((providerUserInfoElement == null) ? null : providerUserInfoElement.getAsJsonArray());
    if (jsonUser.has("providerUserInfo")) {
      JsonArray fedInfo = jsonUser.get("providerUserInfo").getAsJsonArray();
      List<GitkitUser.ProviderInfo> providerInfo = new ArrayList<GitkitUser.ProviderInfo>();
      for (int idp = 0; idp < fedInfo.size(); idp++) {
        JsonObject provider = fedInfo.get(idp).getAsJsonObject();
        displayNameElement = provider.get("displayName");
        photoUrlElement = provider.get("photoUrl");
        providerInfo.add(new GitkitUser.ProviderInfo(
            provider.get("providerId").getAsString(),
            provider.get("federatedId").getAsString(),
            (displayNameElement == null) ? "" : displayNameElement.getAsString(),
            (photoUrlElement == null) ? "" : photoUrlElement.getAsString()));
      }
      user.setProviders(providerInfo);
    }
    return user;
  }

}
