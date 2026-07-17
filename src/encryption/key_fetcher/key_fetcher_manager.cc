// Copyright 2023 Google LLC
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

#include "src/encryption/key_fetcher/key_fetcher_manager.h"

#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "absl/log/log.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_join.h"
#include "absl/time/time.h"
#include "src/encryption/key_fetcher/interface/private_key_fetcher_interface.h"
#include "src/encryption/key_fetcher/interface/public_key_fetcher_interface.h"
#include "src/metric/key_fetch.h"
#include "src/public/cpio/interface/public_key_client/public_key_client_interface.h"

namespace privacy_sandbox::server_common {

namespace {

absl::Status MergeStatuses(absl::Status&& status1, absl::Status&& status2) {
  if (!status1.ok() && !status2.ok()) {
    std::string combined_message = absl::StrCat(
        "Multiple errors: ", status1.message(), "; ", status2.message());
    return absl::Status(absl::StatusCode::kInternal, combined_message);
  }

  status1.Update(status2);
  return status1;
}

// Returns the IDs of the public keys the coordinator is currently publishing to
// clients (empty when there is no public key fetcher, e.g. on servers that only
// decrypt and never encrypt).
std::vector<google::scp::cpio::PublicPrivateKeyPairId>
CollectPublishedPublicKeyIds(PublicKeyFetcherInterface* public_key_fetcher) {
  if (public_key_fetcher == nullptr) {
    return {};
  }
  return public_key_fetcher->GetAllKeyIds();
}

// Startup readiness gate.
//
// Confirms that for every public key currently published to clients there is a
// matching private key in the cache. If not, the service would be unable to
// decrypt requests encrypted with that public key, so we refuse to start.
//
// This is self-limiting and fails safe: in normal operation the published
// public key is also the newest key, which the private key fetcher always
// fetches "by max age", so the check passes. It can only fail when the
// published key is NOT the newest key (i.e. during a key-rotation grace period)
// AND the explicit "by ID" fetch did not produce that private key - which is
// exactly the state in which serving traffic would cause silent decrypt
// failures.
absl::Status ValidatePublishedPrivateKeys(
    PublicKeyFetcherInterface* public_key_fetcher,
    PrivateKeyFetcherInterface* private_key_fetcher) {
  if (public_key_fetcher == nullptr) {
    return absl::OkStatus();
  }

  const std::vector<google::scp::cpio::PublicPrivateKeyPairId>
      published_public_key_ids = public_key_fetcher->GetAllKeyIds();
  std::vector<google::scp::cpio::PublicPrivateKeyPairId> missing_private_keys;
  for (const auto& public_key_id : published_public_key_ids) {
    if (!private_key_fetcher->GetKey(public_key_id).has_value()) {
      missing_private_keys.push_back(public_key_id);
    }
  }

  if (missing_private_keys.empty()) {
    return absl::OkStatus();
  }

  return absl::FailedPreconditionError(absl::StrCat(
      "No private key cached for published public key ID(s): [",
      absl::StrJoin(missing_private_keys, ", "),
      "]. The coordinator is publishing a public key whose private key this "
      "service could not fetch (check that the private key endpoint honors "
      "by-ID lookups during a key-rotation grace period)."));
}

absl::Status RefreshKeys(PublicKeyFetcherInterface* public_key_fetcher,
                         PrivateKeyFetcherInterface* private_key_fetcher) {
  absl::Status key_fetch_result = absl::OkStatus();

  // Refresh public keys FIRST, then collect the IDs currently published to
  // clients so the private key refresh can explicitly fetch the matching
  // private keys. Ordering matters: the private fetch depends on the
  // freshly-updated public key cache.
  std::vector<google::scp::cpio::PublicPrivateKeyPairId>
      published_public_key_ids;
  if (public_key_fetcher) {
    key_fetch_result = public_key_fetcher->Refresh();
    if (!key_fetch_result.ok()) {
      KeyFetchResultCounter::IncrementPublicKeyFetchSyncFailureCount();
      key_fetch_result = absl::Status(
          key_fetch_result.code(), absl::StrCat("Public key refresh failed: ",
                                                 key_fetch_result.message()));
    } else {
      published_public_key_ids =
          CollectPublishedPublicKeyIds(public_key_fetcher);
    }
  }

  absl::Status private_key_refresh_status =
      private_key_fetcher->Refresh(published_public_key_ids);
  if (!private_key_refresh_status.ok()) {
    KeyFetchResultCounter::IncrementPrivateKeyFetchSyncFailureCount();
    private_key_refresh_status =
        absl::Status(private_key_refresh_status.code(),
                     absl::StrCat("Private key refresh failed: ",
                                  private_key_refresh_status.message()));
    key_fetch_result = MergeStatuses(std::move(key_fetch_result),
                                     std::move(private_key_refresh_status));
  }

  return key_fetch_result;
}

}  // namespace

using ::google::cmrt::sdk::public_key_service::v1::PublicKey;
using ::google::scp::cpio::PublicPrivateKeyPairId;
using ::privacy_sandbox::server_common::PrivateKeyFetcherInterface;
using ::privacy_sandbox::server_common::PublicKeyFetcherInterface;

// @param key_refresh_period how often the key refresh flow is to be run.
// @public_key_fetcher client for interacting with the Public Key Service
// @private_key_fetcher client for interacting with the Private Key Service
KeyFetcherManager::KeyFetcherManager(
    absl::Duration key_refresh_period,
    std::unique_ptr<PublicKeyFetcherInterface> public_key_fetcher,
    std::unique_ptr<PrivateKeyFetcherInterface> private_key_fetcher,
    privacy_sandbox::server_common::log::PSLogContext& log_context)
    : key_refresh_period_(key_refresh_period),
      public_key_fetcher_(std::move(public_key_fetcher)),
      private_key_fetcher_(std::move(private_key_fetcher)),
      log_context_(log_context),
      key_refresh_closure_(PeriodicClosure::Create()) {}

KeyFetcherManager::~KeyFetcherManager() { key_refresh_closure_->Stop(); }

absl::Status KeyFetcherManager::Start() noexcept {
  absl::Status key_fetch_status =
      RefreshKeys(public_key_fetcher_.get(), private_key_fetcher_.get());
  if (!key_fetch_status.ok()) {
    PS_LOG(ERROR, log_context_)
        << "Initial key fetch failed: " << key_fetch_status;
    return key_fetch_status;
  }

  // Do not begin serving until every published public key has a matching
  // private key cached. Otherwise the service could accept requests it is
  // unable to decrypt (e.g. a fresh instance started during a grace period).
  absl::Status readiness_status = ValidatePublishedPrivateKeys(
      public_key_fetcher_.get(), private_key_fetcher_.get());
  if (!readiness_status.ok()) {
    PS_LOG(ERROR, log_context_)
        << "Key readiness validation failed: " << readiness_status;
    return readiness_status;
  }

  (void)key_refresh_closure_->StartDelayed(
      key_refresh_period_, [this]() { RunPeriodicKeyRefresh(); });
  return absl::OkStatus();
}

void KeyFetcherManager::RunPeriodicKeyRefresh() {
  absl::Status key_fetch_status =
      RefreshKeys(public_key_fetcher_.get(), private_key_fetcher_.get());
  if (!key_fetch_status.ok()) {
    PS_LOG(ERROR, log_context_) << key_fetch_status;
  }
}

absl::StatusOr<PublicKey> KeyFetcherManager::GetPublicKey(
    CloudPlatform cloud_platform) noexcept {
  return public_key_fetcher_->GetKey(cloud_platform);
}

std::optional<PrivateKey> KeyFetcherManager::GetPrivateKey(
    const google::scp::cpio::PublicPrivateKeyPairId& key_id) noexcept {
  return private_key_fetcher_->GetKey(key_id);
}

std::unique_ptr<KeyFetcherManagerInterface> KeyFetcherManagerFactory::Create(
    absl::Duration key_refresh_period,
    std::unique_ptr<PublicKeyFetcherInterface> public_key_fetcher,
    std::unique_ptr<PrivateKeyFetcherInterface> private_key_fetcher,
    privacy_sandbox::server_common::log::PSLogContext& log_context) {
  return std::make_unique<KeyFetcherManager>(
      key_refresh_period, std::move(public_key_fetcher),
      std::move(private_key_fetcher), log_context);
}

}  // namespace privacy_sandbox::server_common
