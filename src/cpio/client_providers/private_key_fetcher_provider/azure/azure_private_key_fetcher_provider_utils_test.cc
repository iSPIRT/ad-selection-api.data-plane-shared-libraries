// Portions Copyright (c) Microsoft Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "azure_private_key_fetcher_provider_utils.h"

#include <gtest/gtest.h>

#include <memory>
#include <string>

using google::scp::core::HttpMethod;
using google::scp::core::HttpRequest;
using google::scp::cpio::PrivateKeyVendingEndpoint;
using google::scp::cpio::client_providers::AzurePrivateKeyFetchingClientUtils;
using google::scp::cpio::client_providers::PrivateKeyFetchingRequest;

namespace {
constexpr char kPrivateKeyBaseUri[] =
    "http://localhost.test:8000/app/key?fmt=tink";
constexpr char kKeyId[] = "38";

PrivateKeyFetchingRequest MakeRequest() {
  PrivateKeyFetchingRequest request;
  request.key_vending_endpoint = std::make_shared<PrivateKeyVendingEndpoint>();
  request.key_vending_endpoint->private_key_vending_service_endpoint =
      kPrivateKeyBaseUri;
  return request;
}

// Without a key ID the request targets the bare endpoint (fetch "by max age").
TEST(AzurePrivateKeyFetchingClientUtilsTest, CreateHttpRequestWithoutKid) {
  PrivateKeyFetchingRequest request = MakeRequest();

  HttpRequest http_request;
  AzurePrivateKeyFetchingClientUtils::CreateHttpRequest(request, http_request);

  EXPECT_EQ(http_request.method, HttpMethod::POST);
  EXPECT_EQ(*http_request.path, kPrivateKeyBaseUri);
}

// With a key ID the `kid` query parameter is appended (fetch "by ID"), which is
// what lets a service request the specific private key matching the public key
// clients are currently using during a rotation grace period.
TEST(AzurePrivateKeyFetchingClientUtilsTest, CreateHttpRequestWithKid) {
  PrivateKeyFetchingRequest request = MakeRequest();
  request.key_id = std::make_shared<std::string>(kKeyId);

  HttpRequest http_request;
  AzurePrivateKeyFetchingClientUtils::CreateHttpRequest(request, http_request);

  EXPECT_EQ(http_request.method, HttpMethod::POST);
  EXPECT_EQ(*http_request.path,
            "http://localhost.test:8000/app/key?fmt=tink&kid=38");
}

}  // namespace
