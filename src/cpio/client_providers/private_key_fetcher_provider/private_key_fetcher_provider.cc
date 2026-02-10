/*
 * Copyright 2022 Google LLC
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

#include "private_key_fetcher_provider.h"

#include <memory>
#include <utility>

#include <nlohmann/json.hpp>

#include "absl/functional/bind_front.h"
#include "absl/strings/str_cat.h"
#include "src/core/common/global_logger/global_logger.h"
#include "src/core/interface/async_context.h"
#include "src/cpio/client_providers/interface/private_key_fetcher_provider_interface.h"
#include "src/public/core/interface/execution_result.h"

#include "error_codes.h"
#include "private_key_fetcher_provider_utils.h"

using google::scp::core::AsyncContext;
using google::scp::core::ExecutionResult;
using google::scp::core::FailureExecutionResult;
using google::scp::core::HttpRequest;
using google::scp::core::HttpResponse;
using google::scp::core::SuccessExecutionResult;
using google::scp::core::common::kZeroUuid;
using google::scp::core::errors::
    SC_PRIVATE_KEY_FETCHER_PROVIDER_HTTP_CLIENT_NOT_FOUND;
using google::scp::cpio::client_providers::PrivateKeyFetchingRequest;
using google::scp::cpio::client_providers::PrivateKeyFetchingResponse;

namespace {
constexpr std::string_view kPrivateKeyFetcherProvider =
    "PrivateKeyFetcherProvider";
}

namespace google::scp::cpio::client_providers {
ExecutionResult PrivateKeyFetcherProvider::Init() noexcept {
  if (!http_client_) {
    auto execution_result = FailureExecutionResult(
        SC_PRIVATE_KEY_FETCHER_PROVIDER_HTTP_CLIENT_NOT_FOUND);
    SCP_ERROR(kPrivateKeyFetcherProvider, kZeroUuid, execution_result,
              "Failed to get http client.");
    auto error_message = google::scp::core::errors::GetErrorMessage(
        execution_result.status_code);
    PS_LOG(ERROR, log_context_)
        << "Failed to get http client. Error message: " << error_message;
    return execution_result;
  }
  return SuccessExecutionResult();
}

ExecutionResult PrivateKeyFetcherProvider::Run() noexcept {
  return SuccessExecutionResult();
}

ExecutionResult PrivateKeyFetcherProvider::Stop() noexcept {
  return SuccessExecutionResult();
}

ExecutionResult PrivateKeyFetcherProvider::FetchPrivateKey(
    AsyncContext<PrivateKeyFetchingRequest, PrivateKeyFetchingResponse>&
        private_key_fetching_context) noexcept {
  std::string endpoint_url = private_key_fetching_context.request
    ->key_vending_endpoint
    ->private_key_vending_service_endpoint;
  std::string key_info = "";
  if (private_key_fetching_context.request->key_id) {
    key_info = absl::StrCat(" key_id: ", *private_key_fetching_context.request->key_id);
  } else {
    key_info = absl::StrCat(" max_age_seconds: ", 
       private_key_fetching_context.request->max_age_seconds);
  }

  SCP_INFO(kPrivateKeyFetcherProvider, private_key_fetching_context.activity_id,
    "FetchPrivateKey: Starting fetch from endpoint %s.%s",
    endpoint_url.c_str(), key_info.c_str());

  AsyncContext<PrivateKeyFetchingRequest, HttpRequest>
      sign_http_request_context(
          private_key_fetching_context.request,
          absl::bind_front(&PrivateKeyFetcherProvider::SignHttpRequestCallback,
                           this, private_key_fetching_context),
          private_key_fetching_context);

  return SignHttpRequest(sign_http_request_context);
}

void PrivateKeyFetcherProvider::SignHttpRequestCallback(
    AsyncContext<PrivateKeyFetchingRequest, PrivateKeyFetchingResponse>&
        private_key_fetching_context,
    AsyncContext<PrivateKeyFetchingRequest, HttpRequest>&
        sign_http_request_context) noexcept {
  auto execution_result = sign_http_request_context.result;
  if (!execution_result.Successful()) {
    SCP_ERROR_CONTEXT(kPrivateKeyFetcherProvider, private_key_fetching_context,
                      execution_result, "Failed to sign http request.");
    auto error_message = google::scp::core::errors::GetErrorMessage(
        execution_result.status_code);
    PS_LOG(ERROR, log_context_)
        << "Failed to sign http request. Error message: " << error_message;
    private_key_fetching_context.Finish(execution_result);
    return;
  }

  std::string endpoint_url = private_key_fetching_context.request
                                 ->key_vending_endpoint
                                 ->private_key_vending_service_endpoint;
  std::string http_method = "";
  if (sign_http_request_context.response) {
    switch (sign_http_request_context.response->method) {
      case google::scp::core::HttpMethod::GET:
        http_method = "GET";
        break;
      case google::scp::core::HttpMethod::POST:
        http_method = "POST";
        break;
      default:
        http_method = "UNKNOWN";
        break;
    }
  }

  SCP_INFO(kPrivateKeyFetcherProvider, private_key_fetching_context.activity_id,
           "SignHttpRequestCallback: HTTP request signed successfully. Sending %s request to %s",
           http_method.c_str(), endpoint_url.c_str());
  
  AsyncContext<HttpRequest, HttpResponse> http_client_context(
      std::move(sign_http_request_context.response),
      absl::bind_front(&PrivateKeyFetcherProvider::PrivateKeyFetchingCallback,
                       this, private_key_fetching_context),
      private_key_fetching_context);
  execution_result = http_client_->PerformRequest(http_client_context);
  if (!execution_result.Successful()) {
    SCP_ERROR_CONTEXT(
        kPrivateKeyFetcherProvider, private_key_fetching_context,
        execution_result,
        "Failed to perform sign http request to reach endpoint %s.",
        private_key_fetching_context.request->key_vending_endpoint
            ->private_key_vending_service_endpoint.c_str());
    auto error_message = google::scp::core::errors::GetErrorMessage(
        execution_result.status_code);
    PS_LOG(ERROR, log_context_)
        << "Failed to perform sign http request to reach endpoint ."
        << private_key_fetching_context.request->key_vending_endpoint
               ->private_key_vending_service_endpoint.c_str()
        << ". Error message: " << error_message;
    private_key_fetching_context.Finish(execution_result);
  }
}

void PrivateKeyFetcherProvider::PrivateKeyFetchingCallback(
    AsyncContext<PrivateKeyFetchingRequest, PrivateKeyFetchingResponse>&
        private_key_fetching_context,
    AsyncContext<HttpRequest, HttpResponse>& http_client_context) noexcept {
  std::string endpoint_url = private_key_fetching_context.request
        ->key_vending_endpoint
        ->private_key_vending_service_endpoint;

  SCP_INFO(kPrivateKeyFetcherProvider, private_key_fetching_context.activity_id,
    "PrivateKeyFetchingCallback: Received HTTP response from endpoint %s",
    endpoint_url.c_str());

  private_key_fetching_context.result = http_client_context.result;
  if (!http_client_context.result.Successful()) {
    std::string endpoint_url = private_key_fetching_context.request
                                    ->key_vending_endpoint
                                    ->private_key_vending_service_endpoint;
    std::string http_status_info = "";
    std::string response_body_info = "";

    if (http_client_context.response) {
      http_status_info = absl::StrCat(" HTTP status code: ", 
                                       static_cast<int>(http_client_context.response->code));
      if (http_client_context.response->body.bytes &&
          !http_client_context.response->body.bytes->empty()) {
        std::string body_str(http_client_context.response->body.bytes->begin(),
                            http_client_context.response->body.bytes->end());
        // Limit response body length for logging
        constexpr size_t kMaxBodyLogLength = 500;
        if (body_str.length() > kMaxBodyLogLength) {
          body_str = body_str.substr(0, kMaxBodyLogLength) + "... (truncated)";
        }
        response_body_info = absl::StrCat(" Response body: ", body_str);
      }
    }

    SCP_ERROR_CONTEXT(
        kPrivateKeyFetcherProvider, private_key_fetching_context,
        private_key_fetching_context.result,
        "Failed to fetch private key from endpoint %s.%s%s",
        endpoint_url.c_str(), http_status_info.c_str(), response_body_info.c_str());
    auto error_message = google::scp::core::errors::GetErrorMessage(
        private_key_fetching_context.result.status_code);
    PS_LOG(ERROR, log_context_)
        << "Failed to fetch private key from endpoint: " << endpoint_url
        << http_status_info << response_body_info
        << ". Error message: " << error_message;
    private_key_fetching_context.Finish();
    return;
  }

  int http_status_code = 0;
  if (http_client_context.response) {
    http_status_code = static_cast<int>(http_client_context.response->code);
    SCP_INFO(kPrivateKeyFetcherProvider, private_key_fetching_context.activity_id,
             "PrivateKeyFetchingCallback: HTTP response successful. Status code: %d",
             http_status_code);
  }

  PrivateKeyFetchingResponse response;
  auto result = PrivateKeyFetchingClientUtils::ParsePrivateKey(
      http_client_context.response->body, response);
  if (!result.Successful()) {
    SCP_ERROR_CONTEXT(kPrivateKeyFetcherProvider, private_key_fetching_context,
                      result, "Failed to parse private key.");
    auto error_message =
        google::scp::core::errors::GetErrorMessage(result.status_code);
    PS_LOG(ERROR, log_context_)
        << "Failed to parse private key. Error message: " << error_message;
    private_key_fetching_context.Finish(result);
    return;
  }

  SCP_INFO(kPrivateKeyFetcherProvider, private_key_fetching_context.activity_id,
           "PrivateKeyFetchingCallback: Successfully parsed private key. Found %zu encryption keys",
           response.encryption_keys.size());
           
  private_key_fetching_context.response =
      std::make_shared<PrivateKeyFetchingResponse>(response);
  private_key_fetching_context.Finish();
}
}  // namespace google::scp::cpio::client_providers
