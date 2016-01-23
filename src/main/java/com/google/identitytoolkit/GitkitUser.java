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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import com.google.common.collect.Lists;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

/**
 * Wrapper class containing user attributes.
 */
public class GitkitUser {
  private String email;
  private String localId;
  private String name;
  private String photoUrl;
  private String currentProvider;
  private List<ProviderInfo> providers = Lists.newArrayList();
  private byte[] hash;
  private byte[] salt;

  public String getEmail() {
    return email;
  }

  public GitkitUser setEmail(String email) {
    this.email = email;
    return this;
  }

  public String getLocalId() {
    return localId;
  }

  public GitkitUser setLocalId(String localId) {
    this.localId = localId;
    return this;
  }

  public String getName() {
    return name;
  }

  public GitkitUser setName(String name) {
    this.name = name;
    return this;
  }

  public String getPhotoUrl() {
    return photoUrl;
  }

  public GitkitUser setPhotoUrl(String photoUrl) {
    this.photoUrl = photoUrl;
    return this;
  }

  public String getCurrentProvider() {
    return currentProvider;
  }

  public GitkitUser setCurrentProvider(String currentProvider) {
    this.currentProvider = currentProvider;
    return this;
  }

  public List<ProviderInfo> getProviders() {
    return providers;
  }

  public GitkitUser setProviders(JsonArray providers) {
    List<ProviderInfo> providerInfo = new ArrayList<ProviderInfo>();
    if (providers != null) {
      for (int i = 0; i < providers.size(); i++) {
        JsonObject provider = providers.get(i).getAsJsonObject();
        JsonElement displayNameElement = provider.get("displayName");
        JsonElement photoUrlElement = provider.get("photoUrl");
        providerInfo.add(new ProviderInfo(
            provider.get("providerId").getAsString(),
            provider.get("federatedId").getAsString(),
            (displayNameElement == null) ? "" : displayNameElement.getAsString(),
            (photoUrlElement == null) ? "" : photoUrlElement.getAsString()));
      }
    }
    this.providers = providerInfo;
    return this;
  }

  public GitkitUser setProviders(List<ProviderInfo> providers) {
    this.providers.clear();
    this.providers.addAll(providers);
    return this;
  }

  public byte[] getHash() {
    return hash;
  }

  public GitkitUser setHash(byte[] hash) {
    this.hash = Arrays.copyOf(hash, hash.length);
    return this;
  }

  public byte[] getSalt() {
    return salt;
  }

  public GitkitUser setSalt(byte[] salt) {
    this.salt = Arrays.copyOf(salt, salt.length);
    return this;
  }

  @Override
  public String toString() {
    StringBuilder stringBuilder = new StringBuilder("[")
        .append("\n\tlocalId: ").append(localId)
        .append("\n\temail: ").append(email)
        .append("\n\tname: ").append(name)
        .append("\n\tphotoUrl: ").append(photoUrl)
        .append("\n\tcurrent idp: ").append(currentProvider)
        .append("\n\tproviders: [");
    for (ProviderInfo providerInfo : providers) {
      stringBuilder
          .append("\n\t\tidp: ").append(providerInfo.getProviderId())
          .append("\n\t\tfedId: ").append(providerInfo.getFederatedId())
          .append("\n\t\tname: ").append(providerInfo.getName())
          .append("\n\t\tphotoUrl: ").append(providerInfo.getPhotoUrl());
    }
    return stringBuilder.append("]\n]").toString();
  }

  /**
   * Wrapper class containing the associated identity providers of a user.
   */
  public static class ProviderInfo {
    private final String providerId;
    private final String federatedId;
    private final String name;
    private final String photoUrl;

    public ProviderInfo(String providerId, String federatedId, String name, String photoUrl) {
      this.providerId = providerId;
      this.federatedId = federatedId;
      this.name = name;
      this.photoUrl = photoUrl;
    }

    public String getProviderId() {
      return providerId;
    }

    public String getFederatedId() {
      return federatedId;
    }

    public String getName() {
      return name;
    }

    public String getPhotoUrl() {
      return photoUrl;
    }
  }
}
