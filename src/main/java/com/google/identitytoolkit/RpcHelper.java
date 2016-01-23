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

import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPrivateKey;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.joda.time.Instant;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.Maps;
import com.google.common.io.BaseEncoding;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonPrimitive;

import net.oauth.jsontoken.JsonToken;
import net.oauth.jsontoken.crypto.RsaSHA256Signer;

/**
 * Wraps the http interactions for Gitkit APIs.
 */
public class RpcHelper {

  @VisibleForTesting
  static final String GITKIT_SCOPE = "https://www.googleapis.com/auth/identitytoolkit";
  @VisibleForTesting
  static final String TOKEN_SERVER = "https://accounts.google.com/o/oauth2/token";

  private static final Logger log = Logger.getLogger(RpcHelper.class.getName());
  private final RsaSHA256Signer signer;
  private final String gitkitApiUrl;
  private final HttpSender httpSender;

  public RpcHelper(HttpSender httpSender, String gitkitApiUrl, String serviceAccountEmail,
      InputStream keyStream) {
    this.gitkitApiUrl = gitkitApiUrl;
    this.httpSender = httpSender;
    signer = initRsaSHA256Signer(serviceAccountEmail, keyStream);
  }

  public JsonObject createAuthUri(String identifier, String continueUri, String context)
      throws GitkitServerException, GitkitClientException {
    JsonObject params = new JsonObject();
    if (identifier != null) {
      params.addProperty("identifier", identifier);
    }
    if (continueUri != null) {
      params.addProperty("continueUri", continueUri);
    }
    if (context != null) {
      params.addProperty("context", context);
    }
    return invokeGitkitApi("createAuthUri", params, null);
  }

  public JsonObject verifyAssertion(String requestUri, String postBody)
      throws GitkitServerException, GitkitClientException {
    JsonObject params = new JsonObject();
    params.addProperty("requestUri", requestUri);
    if (postBody != null) {
      params.addProperty("postBody", postBody);
    }
    return invokeGitkitApi("verifyAssertion", params, null);
  }

  public JsonObject verifyPassword(String email, String password, String pendingIdToken, String captchaResponse)
      throws GitkitServerException, GitkitClientException {
    JsonObject params = new JsonObject();
    params.addProperty("email", email);
    params.addProperty("password", password);
    if (pendingIdToken != null) {
      params.addProperty("pendingIdToken", pendingIdToken);
    }
    if (captchaResponse != null) {
      params.addProperty("captchaResponse", captchaResponse);
    }
    return invokeGoogle2LegOauthApi("verifyPassword", params);
  }

  public JsonObject getOobCode(JsonObject resetReq)
      throws GitkitClientException, GitkitServerException {
    return invokeGoogle2LegOauthApi("getOobConfirmationCode", resetReq);
  }

  /**
   * Uses idToken to retrieve the user account information from GITkit service.
   *
   * @param idToken
   */
  public JsonObject getAccountInfo(String idToken)
      throws GitkitClientException, GitkitServerException {
    // Uses idToken to make the server call to GITKit
    JsonObject params = new JsonObject();
    params.addProperty("idToken", idToken);
    return invokeGoogle2LegOauthApi("getAccountInfo", params);
  }

  /**
   * Using 2-Leg Oauth (i.e. Service Account).
   */
  public JsonObject getAccountInfoById(String localId)
      throws GitkitClientException, GitkitServerException {
    JsonObject params = new JsonObject();
    JsonArray localIdArray = new JsonArray();
    localIdArray.add(new JsonPrimitive(localId));
    params.add("localId", localIdArray);
    return invokeGoogle2LegOauthApi("getAccountInfo", params);
  }

  /**
   * Using 2-Leg Oauth (i.e. Service Account).
   */
  public JsonObject getAccountInfoByEmail(String email)
      throws GitkitClientException, GitkitServerException {
    JsonObject params = new JsonObject();
    JsonArray emailArray = new JsonArray();
    emailArray.add(new JsonPrimitive(email));
    params.add("email", emailArray);
    return invokeGoogle2LegOauthApi("getAccountInfo", params);
  }

  public JsonObject updateAccount(GitkitUser account)
      throws GitkitServerException, GitkitClientException {
    JsonObject params = new JsonObject();
    params.addProperty("email", account.getEmail());
    params.addProperty("localId", account.getLocalId());
    if (account.getName() != null) {
      params.addProperty("displayName", account.getName());
    }
    if (account.getHash() != null) {
      params.addProperty("password", new String(account.getHash()));
    }
    return invokeGoogle2LegOauthApi("setAccountInfo", params);
  }

  public JsonObject downloadAccount(String nextPageToken, Integer maxResults)
      throws GitkitClientException, GitkitServerException {
    JsonObject params = new JsonObject();
    if (nextPageToken != null) {
      params.addProperty("nextPageToken", nextPageToken);
    }
    if (maxResults != null) {
      params.addProperty("maxResults", maxResults);
    }
    return invokeGoogle2LegOauthApi("downloadAccount", params);
  }

  public JsonObject uploadAccount(String hashAlgorithm, byte[] hashKey, List<GitkitUser> accounts,
                                  byte[] saltSeparator, Integer rounds, Integer memoryCost)
          throws GitkitClientException, GitkitServerException {
    JsonObject params = new JsonObject();
    params.addProperty("hashAlgorithm", hashAlgorithm);
    params.addProperty("signerKey", BaseEncoding.base64Url().encode(hashKey));
    params.add("users", toJsonArray(accounts));
      if (saltSeparator != null) {
          params.addProperty("saltSeparator", BaseEncoding.base64Url().encode(saltSeparator));
      }
      if (rounds != null) {
          params.addProperty("rounds", rounds);
      }
      if (memoryCost != null) {
          params.addProperty("memoryCost", memoryCost);
      }
    return invokeGoogle2LegOauthApi("uploadAccount", params);
  }

  public JsonObject deleteAccount(String localId)
      throws GitkitClientException, GitkitServerException {
    JsonObject params = new JsonObject();
    params.addProperty("localId", localId);
    return invokeGoogle2LegOauthApi("deleteAccount", params);
  }

  String downloadCerts(String serverApiKey) throws IOException {
    String certUrl = gitkitApiUrl + "publicKeys";
    Map<String, String> headers = Maps.newHashMap();
    if (serverApiKey != null) {
      certUrl += "?key=" + serverApiKey;
    } else {
      try {
        headers.put("Authorization", "Bearer " + getAccessToken());
      } catch (GeneralSecurityException e) {
        throw new IOException(e);
      }
    }
    return httpSender.get(certUrl, headers);
  }

  @VisibleForTesting
  JsonObject invokeGoogle2LegOauthApi(String method, JsonObject req)
      throws GitkitClientException, GitkitServerException {
    try {
      String accessToken = getAccessToken();
      return invokeGitkitApi(method, req, accessToken);
    } catch (GeneralSecurityException e) {
      throw new GitkitServerException(e);
    } catch (IOException e) {
      throw new GitkitServerException(e);
    }
  }

  @VisibleForTesting
  String getAccessToken() throws GeneralSecurityException, IOException {
    String assertion = signServiceAccountRequest();
    String data = "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion="
        + assertion;
    Map<String, String> headers = Maps.newHashMap();
    headers.put("Content-Type", "application/x-www-form-urlencoded");
    String response = httpSender.post(TOKEN_SERVER, data, headers);
    JsonObject responseObject = new JsonParser().parse(response).getAsJsonObject();
    return responseObject.get("access_token").getAsString();
  }

  @VisibleForTesting
  String signServiceAccountRequest() throws GeneralSecurityException {
    JsonToken assertion = new JsonToken(signer);
    assertion.setAudience(TOKEN_SERVER);
    assertion.setParam("nonce", "nonce");
    assertion.setParam("scope", GITKIT_SCOPE);
    assertion.setIssuedAt(new Instant());
    assertion.setExpiration(new Instant().plus(60 * 60 * 1000));
    return assertion.serializeAndSign();
  }

  private JsonObject invokeGitkitApi(String method, JsonObject params, String accessToken)
      throws GitkitClientException, GitkitServerException {
    try {
      Map<String, String> headers = Maps.newHashMap();
      if (accessToken != null) {
        headers.put("Authorization", "Bearer " + accessToken);
      }
      headers.put("Content-Type", "application/json");
      String response = httpSender.post(gitkitApiUrl + method, params.toString(), headers);
      return checkGitkitException(response);
    } catch (IOException e) {
      throw new GitkitServerException(e);
    }
  }

  private RsaSHA256Signer initRsaSHA256Signer(String serviceAccountEmail, InputStream keyStream) {
    try {
      if (serviceAccountEmail != null && keyStream != null) {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(keyStream, "notasecret".toCharArray());
        return new RsaSHA256Signer(
            serviceAccountEmail,
            null,
            (RSAPrivateKey) keyStore.getKey("privatekey", "notasecret".toCharArray()));
      }
    } catch (KeyStoreException e) {
      log.log(Level.WARNING, "can not initialize service account signer: " + e.getMessage(), e);
    } catch (CertificateException e) {
      log.log(Level.WARNING, "can not initialize service account signer: " + e.getMessage(), e);
    } catch (UnrecoverableKeyException e) {
      log.log(Level.WARNING, "can not initialize service account signer: " + e.getMessage(), e);
    } catch (NoSuchAlgorithmException e) {
      log.log(Level.WARNING, "can not initialize service account signer: " + e.getMessage(), e);
    } catch (IOException e) {
      log.log(Level.WARNING, "can not initialize service account signer: " + e.getMessage(), e);
    } catch (InvalidKeyException e) {
      log.log(Level.WARNING, "can not initialize service account signer: " + e.getMessage(), e);
    }
    log.warning("service account is set to null due to: email = " + serviceAccountEmail
        + "keystream = " + keyStream);
    return null;
  }

  private static JsonArray toJsonArray(List<GitkitUser> accounts) {
    JsonArray infos = new JsonArray();
    for (GitkitUser account : accounts) {
      JsonObject user = new JsonObject();
      user.addProperty("email", account.getEmail());
      user.addProperty("localId", account.getLocalId());
      if (account.getHash() != null) {
        user.addProperty("passwordHash", BaseEncoding.base64Url().encode(account.getHash()));
      }
      if (account.getSalt() != null) {
        user.addProperty("salt", BaseEncoding.base64Url().encode(account.getSalt()));
      }
      if (account.getProviders() != null) {
        JsonArray providers = new JsonArray();
        for (GitkitUser.ProviderInfo idpInfo : account.getProviders()) {
          JsonObject provider = new JsonObject();
          provider.addProperty("federatedId", idpInfo.getFederatedId());
          provider.addProperty("providerId", idpInfo.getProviderId());
          providers.add(provider);
        }
        user.add("providerUserInfo", providers);
      }
      infos.add(user);
    }
    return infos;
  }

  @VisibleForTesting
  JsonObject checkGitkitException(String response)
      throws GitkitClientException, GitkitServerException {
    JsonElement resultElement = new JsonParser().parse(response);
    if (!resultElement.isJsonObject()) {
      throw new GitkitServerException("null error code from Gitkit server");
    }
    JsonObject result = resultElement.getAsJsonObject();
    if (!result.has("error")) {
      return result;
    }
    // Error handling
    JsonObject error = result.getAsJsonObject("error");
    JsonElement codeElement = error.get("code");
    if (codeElement != null) {
      JsonElement messageElement = error.get("message");
      String message = (messageElement == null) ? "" : messageElement.getAsString();
      if (codeElement.getAsString().startsWith("4")) {
        // 4xx means client input error
        throw new GitkitClientException(message);
      } else {
        throw new GitkitServerException(message);
      }
    }
    throw new GitkitServerException("null error code from Gitkit server");
  }
}
