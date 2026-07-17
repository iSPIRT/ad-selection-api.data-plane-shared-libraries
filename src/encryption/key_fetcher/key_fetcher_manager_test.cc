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

#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <grpc/event_engine/event_engine.h>
#include <grpc/grpc.h>

#include "absl/strings/match.h"
#include "absl/synchronization/blocking_counter.h"
#include "absl/time/clock.h"
#include "googletest/include/gtest/gtest.h"
#include "include/gtest/gtest.h"
#include "src/encryption/key_fetcher/interface/private_key_fetcher_interface.h"
#include "src/encryption/key_fetcher/mock/mock_private_key_fetcher.h"
#include "src/encryption/key_fetcher/mock/mock_public_key_fetcher.h"

namespace privacy_sandbox::server_common {
namespace {

using ::google::scp::cpio::PublicPrivateKeyPairId;
using ::testing::Return;

class KeyFetcherManagerTest : public ::testing::Test {
 protected:
  KeyFetcherManagerTest() {
    public_key_fetcher_ = std::make_unique<MockPublicKeyFetcher>();
    private_key_fetcher_ = std::make_unique<MockPrivateKeyFetcher>();
  }

  std::unique_ptr<MockPublicKeyFetcher> public_key_fetcher_;
  std::unique_ptr<MockPrivateKeyFetcher> private_key_fetcher_;
};

TEST_F(KeyFetcherManagerTest, SuccessfulRefresh) {
  EXPECT_CALL(*public_key_fetcher_, Refresh).WillOnce([&]() -> absl::Status {
    return absl::OkStatus();
  });
  EXPECT_CALL(*public_key_fetcher_, GetAllKeyIds)
      .WillRepeatedly(Return(std::vector<PublicPrivateKeyPairId>{}));
  EXPECT_CALL(*private_key_fetcher_, Refresh)
      .WillOnce([&](const std::vector<PublicPrivateKeyPairId>&) -> absl::Status {
        return absl::OkStatus();
      });

  KeyFetcherManager manager(absl::Minutes(1), std::move(public_key_fetcher_),
                            std::move(private_key_fetcher_));

  auto start_result = manager.Start();
  ASSERT_TRUE(start_result.ok());
}

TEST_F(KeyFetcherManagerTest, NullPointerForPublicKeyFetcher) {
  EXPECT_CALL(*private_key_fetcher_, Refresh)
      .WillOnce([](const std::vector<PublicPrivateKeyPairId>&) {
        return absl::OkStatus();
      });

  KeyFetcherManager manager(absl::Minutes(1), /* public_key_fetcher= */ nullptr,
                            std::move(private_key_fetcher_));

  auto start_result = manager.Start();
  ASSERT_TRUE(start_result.ok());
}

TEST_F(KeyFetcherManagerTest, ValidateErrorMessageOnPublicKeyFetchFailure) {
  EXPECT_CALL(*public_key_fetcher_, Refresh).WillOnce([&]() -> absl::Status {
    return absl::InternalError("public key fetch failed");
  });
  EXPECT_CALL(*private_key_fetcher_, Refresh)
      .WillOnce([&](const std::vector<PublicPrivateKeyPairId>&) -> absl::Status {
        return absl::OkStatus();
      });

  KeyFetcherManager manager(absl::Minutes(1), std::move(public_key_fetcher_),
                            std::move(private_key_fetcher_));

  auto start_result = manager.Start();
  ASSERT_FALSE(start_result.ok());
  ASSERT_TRUE(
      absl::StrContains(start_result.message(), "public key fetch failed"));
}

TEST_F(KeyFetcherManagerTest, ValidateErrorMessageOnPrivateKeyFetchFailure) {
  EXPECT_CALL(*public_key_fetcher_, Refresh).WillOnce([&]() -> absl::Status {
    return absl::OkStatus();
  });
  EXPECT_CALL(*public_key_fetcher_, GetAllKeyIds)
      .WillRepeatedly(Return(std::vector<PublicPrivateKeyPairId>{}));
  EXPECT_CALL(*private_key_fetcher_, Refresh)
      .WillOnce([&](const std::vector<PublicPrivateKeyPairId>&) -> absl::Status {
        return absl::InternalError("private key fetch failed");
      });

  KeyFetcherManager manager(absl::Minutes(1), std::move(public_key_fetcher_),
                            std::move(private_key_fetcher_));

  auto start_result = manager.Start();
  ASSERT_FALSE(start_result.ok());
  ASSERT_TRUE(
      absl::StrContains(start_result.message(), "private key fetch failed"));
}

TEST_F(KeyFetcherManagerTest,
       ValidateErrorMessageOnPublicAndPrivateKeyFetchFailure) {
  EXPECT_CALL(*public_key_fetcher_, Refresh).WillOnce([&]() -> absl::Status {
    return absl::InternalError("public key fetch failed");
  });
  EXPECT_CALL(*private_key_fetcher_, Refresh)
      .WillOnce([&](const std::vector<PublicPrivateKeyPairId>&) -> absl::Status {
        return absl::InternalError("private key fetch failed");
      });

  KeyFetcherManager manager(absl::Minutes(1), std::move(public_key_fetcher_),
                            std::move(private_key_fetcher_));

  auto start_result = manager.Start();
  ASSERT_FALSE(start_result.ok());
  ASSERT_TRUE(
      absl::StrContains(start_result.message(), "public key fetch failed"));
  ASSERT_TRUE(
      absl::StrContains(start_result.message(), "private key fetch failed"));
}

// The readiness gate: if the coordinator is publishing a public key for which
// the service has no matching private key (e.g. a fresh instance during a
// grace period whose by-ID fetch did not succeed), Start() must fail so the
// service does not accept traffic it cannot decrypt.
TEST_F(KeyFetcherManagerTest, FailsStartWhenPublishedPrivateKeyMissing) {
  EXPECT_CALL(*public_key_fetcher_, Refresh).WillOnce([&]() -> absl::Status {
    return absl::OkStatus();
  });
  EXPECT_CALL(*public_key_fetcher_, GetAllKeyIds)
      .WillRepeatedly(Return(std::vector<PublicPrivateKeyPairId>{"38"}));
  EXPECT_CALL(*private_key_fetcher_, Refresh)
      .WillOnce([&](const std::vector<PublicPrivateKeyPairId>&) -> absl::Status {
        return absl::OkStatus();
      });
  EXPECT_CALL(*private_key_fetcher_, GetKey)
      .WillRepeatedly(Return(std::optional<PrivateKey>(std::nullopt)));

  KeyFetcherManager manager(absl::Minutes(1), std::move(public_key_fetcher_),
                            std::move(private_key_fetcher_));

  auto start_result = manager.Start();
  ASSERT_FALSE(start_result.ok());
  ASSERT_TRUE(
      absl::StrContains(start_result.message(), "published public key ID"));
}

// When the published public key does have a matching private key cached, the
// readiness gate passes and the service starts.
TEST_F(KeyFetcherManagerTest, StartsWhenPublishedPrivateKeyPresent) {
  EXPECT_CALL(*public_key_fetcher_, Refresh).WillOnce([&]() -> absl::Status {
    return absl::OkStatus();
  });
  EXPECT_CALL(*public_key_fetcher_, GetAllKeyIds)
      .WillRepeatedly(Return(std::vector<PublicPrivateKeyPairId>{"38"}));
  EXPECT_CALL(*private_key_fetcher_, Refresh)
      .WillOnce([&](const std::vector<PublicPrivateKeyPairId>&) -> absl::Status {
        return absl::OkStatus();
      });
  PrivateKey cached_key;
  cached_key.key_id = "38";
  EXPECT_CALL(*private_key_fetcher_, GetKey)
      .WillRepeatedly(Return(std::optional<PrivateKey>(cached_key)));

  KeyFetcherManager manager(absl::Minutes(1), std::move(public_key_fetcher_),
                            std::move(private_key_fetcher_));

  auto start_result = manager.Start();
  ASSERT_TRUE(start_result.ok());
}

}  // namespace
}  // namespace privacy_sandbox::server_common
