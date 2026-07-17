/*
 * Portions Copyright (c) Microsoft Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <memory>
#include <string>
#include <string_view>
#include <utility>

#include "absl/log/check.h"
#include "absl/strings/match.h"
#include "absl/strings/str_cat.h"
#include "src/azure/attestation/src/attestation.h"

#include "azure_private_key_fetcher_provider_utils.h"

using google::scp::azure::attestation::fetchFakeSnpAttestation;
using google::scp::azure::attestation::fetchSnpAttestation;
using google::scp::azure::attestation::hasSnp;
using google::scp::core::HttpMethod;
using google::scp::core::HttpRequest;
using google::scp::core::Uri;
using google::scp::cpio::client_providers::AzurePrivateKeyFetchingClientUtils;

namespace {
constexpr char kAttestation[] = "attestation";
constexpr char kKidQueryParam[] = "kid";

// Appends the requested key ID to the private key endpoint as a `kid` query
// parameter. This is how a specific (possibly not-newest) private key is
// requested from the coordinator, so a service can fetch the private key that
// matches the public key clients are currently using during a key-rotation
// grace period. Handles endpoints that already carry a query string (e.g.
// ".../app/key?fmt=tink").
std::string BuildPrivateKeyEndpointUri(std::string_view base_uri,
                                       std::string_view key_id) {
  const char separator = absl::StrContains(base_uri, '?') ? '&' : '?';
  return absl::StrCat(base_uri, std::string(1, separator), kKidQueryParam, "=",
                      key_id);
}
}  // namespace

namespace google::scp::cpio::client_providers {
void AzurePrivateKeyFetchingClientUtils::CreateHttpRequest(
    const PrivateKeyFetchingRequest& request, HttpRequest& http_request) {
  const auto& base_uri =
      request.key_vending_endpoint->private_key_vending_service_endpoint;
  http_request.method = HttpMethod::POST;

  // When a specific key ID is requested (fetch "by ID"), pass it to the
  // coordinator via the `kid` query parameter. Otherwise fall back to the bare
  // endpoint, which returns the latest key(s) (fetch "by max age").
  if (request.key_id && !request.key_id->empty()) {
    http_request.path = std::make_shared<Uri>(
        BuildPrivateKeyEndpointUri(base_uri, *request.key_id));
  } else {
    http_request.path = std::make_shared<Uri>(base_uri);
  }

  // Get Attestation Report
  CHECK(hasSnp()) << "It's not in a SNP environment";
  const auto report = fetchSnpAttestation("");
  CHECK(report.has_value()) << "Failed to get attestation report";

  nlohmann::json json_obj;
  json_obj[kAttestation] = report.value();

  http_request.body = core::BytesBuffer(json_obj.dump());
}

}  // namespace google::scp::cpio::client_providers
