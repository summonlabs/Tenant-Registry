// Copyright 2026 Summon Software Labs
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <limits>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>

#include "test_support.hpp"

namespace treg_test {
namespace {

using tenant_registry::advance;
using tenant_registry::ContentDigest;
using tenant_registry::ControlEpoch;
using tenant_registry::DomainGeneration;
using tenant_registry::ErrorCode;
using tenant_registry::Incarnation;
using tenant_registry::is_valid_utf8;
using tenant_registry::JournalSequence;
using tenant_registry::parse_subject_kind;
using tenant_registry::RegistryGeneration;
using tenant_registry::SourceId;
using tenant_registry::SubjectKind;
using tenant_registry::validate_text_field;

/// Builds a byte string from explicit byte values, so a test that needs a
/// truncated or overlong UTF-8 sequence cannot be tripped by a hex escape that
/// silently swallows the character after it.
std::string bytes_of(std::initializer_list<int> values) {
  std::string out;
  out.reserve(values.size());
  for (const int value : values) {
    out.push_back(static_cast<char>(static_cast<unsigned char>(value)));
  }
  return out;
}

constexpr std::uint64_t kCounterMaximum = std::numeric_limits<std::uint64_t>::max();

}  // namespace

TREG_TEST(ids, identity_length_bounds) {
  TREG_CHECK_EQ(TenantId::rules().max_length, static_cast<std::size_t>(128));
  TREG_CHECK_EQ(ServiceId::rules().max_length, static_cast<std::size_t>(128));
  TREG_CHECK_EQ(IsolationDomainId::rules().max_length, static_cast<std::size_t>(128));
  TREG_CHECK_EQ(PrincipalId::rules().max_length, static_cast<std::size_t>(128));
  TREG_CHECK_EQ(SourceId::rules().max_length, static_cast<std::size_t>(128));
  TREG_CHECK_EQ(MetadataKey::rules().max_length, static_cast<std::size_t>(96));

  const std::string at_identity_limit(128, 'a');
  const std::string over_identity_limit(129, 'a');
  const std::string at_key_limit(96, 'k');
  const std::string over_key_limit(97, 'k');

  TREG_CHECK(TenantId::create(at_identity_limit).has_value());
  TREG_CHECK_CODE(TenantId::create(over_identity_limit), ErrorCode::InvalidIdentity);
  TREG_CHECK(ServiceId::create(at_identity_limit).has_value());
  TREG_CHECK_CODE(ServiceId::create(over_identity_limit), ErrorCode::InvalidIdentity);
  TREG_CHECK(IsolationDomainId::create(at_identity_limit).has_value());
  TREG_CHECK_CODE(IsolationDomainId::create(over_identity_limit), ErrorCode::InvalidIdentity);
  TREG_CHECK(PrincipalId::create(at_identity_limit).has_value());
  TREG_CHECK_CODE(PrincipalId::create(over_identity_limit), ErrorCode::InvalidIdentity);
  TREG_CHECK(SourceId::create(at_identity_limit).has_value());
  TREG_CHECK_CODE(SourceId::create(over_identity_limit), ErrorCode::InvalidIdentity);
  TREG_CHECK(MetadataKey::create(at_key_limit).has_value());
  TREG_CHECK_CODE(MetadataKey::create(over_key_limit), ErrorCode::InvalidIdentity);

  // One byte is enough; an empty token is not an identity.
  TREG_CHECK(TenantId::create("a").has_value());
  TREG_CHECK_CODE(TenantId::create(""), ErrorCode::InvalidIdentity);
  TREG_CHECK_CODE(ServiceId::create(""), ErrorCode::InvalidIdentity);
  TREG_CHECK_CODE(IsolationDomainId::create(""), ErrorCode::InvalidIdentity);
  TREG_CHECK_CODE(PrincipalId::create(""), ErrorCode::InvalidIdentity);
  TREG_CHECK_CODE(SourceId::create(""), ErrorCode::InvalidIdentity);
  TREG_CHECK_CODE(MetadataKey::create(""), ErrorCode::InvalidIdentity);

  TREG_CHECK_EQ(std::string_view{TenantId::rules().kind_tag}, std::string_view{"tenant"});
  TREG_CHECK_EQ(std::string_view{MetadataKey::rules().kind_tag}, std::string_view{"metadata_key"});
  TREG_CHECK_EQ(std::string_view{TenantId::create("acme").value().kind_token()}, std::string_view{"tenant"});
}

TREG_TEST(ids, identity_charset_and_boundary_characters) {
  const std::string accepted[] = {"a",  "A",  "0",  "z9",        "a.b",       "a_b",
                                  "a:b", "a-b", "A1.b_c:d-e", "9z", "tenant.one:2", "x.y.z"};
  for (const std::string& candidate : accepted) {
    TREG_CHECK(TenantId::create(candidate).has_value());
  }

  const std::string refused[] = {
      ".a",   "_a",  ":a",  "-a",  "a.",  "a_",   "a:",   "a-",  "a b", "a!b", "a@b", "a/b", "a\\b",
      "a+b",  "a*b", "a#b", "a$b", "a%b", "a,b",  "a;b",  "a=b", "a?b", "a[b", "a]b", "a{b", "a}b",
      "a(b",  "a)b", "a'b", "a\"b", "a`b", "a~b",  "a<b",  "a>b", "a|b", "a^b", "a&b"};
  for (const std::string& candidate : refused) {
    TREG_CHECK_CODE(TenantId::create(candidate), ErrorCode::InvalidIdentity);
  }

  // Bytes below 0x20 and 0x7F are never part of a canonical token.
  TREG_CHECK_CODE(TenantId::create(bytes_of({'a', 0x09, 'b'})), ErrorCode::InvalidIdentity);
  TREG_CHECK_CODE(TenantId::create(bytes_of({'a', 0x0A, 'b'})), ErrorCode::InvalidIdentity);
  TREG_CHECK_CODE(TenantId::create(bytes_of({'a', 0x00, 'b'})), ErrorCode::InvalidIdentity);
  TREG_CHECK_CODE(TenantId::create(bytes_of({'a', 0x1F, 'b'})), ErrorCode::InvalidIdentity);
  TREG_CHECK_CODE(TenantId::create(bytes_of({'a', 0x7F, 'b'})), ErrorCode::InvalidIdentity);

  // A separator is legal in the middle, and only in the middle.
  TREG_CHECK(TenantId::create("a.b_c:d-e").has_value());
  TREG_CHECK(TenantId::create("a..b").has_value());
  TREG_CHECK(TenantId::create("a--b").has_value());
  TREG_CHECK_CODE(TenantId::create("."), ErrorCode::InvalidIdentity);
  TREG_CHECK_CODE(TenantId::create("-"), ErrorCode::InvalidIdentity);
  TREG_CHECK_CODE(TenantId::create("_"), ErrorCode::InvalidIdentity);
  TREG_CHECK_CODE(TenantId::create(":"), ErrorCode::InvalidIdentity);
}

TREG_TEST(ids, identity_is_case_sensitive_and_never_normalised) {
  const TenantId mixed = tenant_id("Acme.Prod");
  TREG_CHECK_EQ(mixed.value(), std::string{"Acme.Prod"});
  TREG_CHECK_EQ(mixed.to_text(), std::string{"Acme.Prod"});
  TREG_CHECK(mixed != tenant_id("acme.prod"));
  TREG_CHECK(tenant_id("ACME") != tenant_id("acme"));
  TREG_CHECK(tenant_id("acme") == tenant_id("acme"));
  TREG_CHECK(tenant_id("acme") < tenant_id("acme2"));

  // Surrounding whitespace is a different identity, not a padded one.
  TREG_CHECK_CODE(TenantId::create(" acme"), ErrorCode::InvalidIdentity);
  TREG_CHECK_CODE(TenantId::create("acme "), ErrorCode::InvalidIdentity);
  TREG_CHECK_CODE(TenantId::create("\tacme"), ErrorCode::InvalidIdentity);

  // Case is part of the digest: two identities that differ only in case are two
  // different identities everywhere.
  TREG_CHECK(TenantId::create("Acme").value().digest() != TenantId::create("acme").value().digest());
}

TREG_TEST(ids, identity_utf8_rules) {
  TREG_CHECK(is_valid_utf8(""));
  TREG_CHECK(is_valid_utf8("plain-ascii.1"));
  TREG_CHECK(is_valid_utf8(bytes_of({0x63, 0x61, 0x66, 0xC3, 0xA9})));            // "caf" + U+00E9
  TREG_CHECK(is_valid_utf8(bytes_of({0xF0, 0x9F, 0x98, 0x80})));                  // U+1F600
  TREG_CHECK(!is_valid_utf8(bytes_of({0x80})));                                   // lone continuation
  TREG_CHECK(!is_valid_utf8(bytes_of({0xC0, 0x80})));                             // overlong NUL
  TREG_CHECK(!is_valid_utf8(bytes_of({0xC1, 0xBF})));                             // overlong
  TREG_CHECK(!is_valid_utf8(bytes_of({0xE0, 0x80, 0x80})));                       // overlong
  TREG_CHECK(!is_valid_utf8(bytes_of({0xED, 0xA0, 0x80})));                       // surrogate U+D800
  TREG_CHECK(!is_valid_utf8(bytes_of({0xF4, 0x90, 0x80, 0x80})));                 // above U+10FFFF
  TREG_CHECK(!is_valid_utf8(bytes_of({0xFF})));                                   // never a lead byte
  TREG_CHECK(!is_valid_utf8(bytes_of({0xC3})));                                   // truncated
  TREG_CHECK(!is_valid_utf8(bytes_of({0xE2, 0x82})));                             // truncated
  TREG_CHECK(!is_valid_utf8(bytes_of({0x61, 0xC3, 0x28, 0x62})));                 // bad continuation

  // Malformed UTF-8 is refused before the charset is even considered.
  TREG_CHECK_CODE(TenantId::create(bytes_of({0x61, 0xC3, 0x28, 0x62})), ErrorCode::InvalidIdentity);
  TREG_CHECK_CODE(TenantId::create(bytes_of({0x80})), ErrorCode::InvalidIdentity);
  // Well formed UTF-8 that is outside the token charset is refused too: an
  // identity is an opaque ASCII token, not arbitrary text.
  TREG_CHECK_CODE(TenantId::create(bytes_of({0x63, 0x61, 0x66, 0xC3, 0xA9})), ErrorCode::InvalidIdentity);
  TREG_CHECK_CODE(TenantId::create(bytes_of({0xE2, 0x82, 0xAC})), ErrorCode::InvalidIdentity);
}

TREG_TEST(ids, identity_classes_are_distinct_types) {
  static_assert(!std::is_same_v<TenantId, ServiceId>, "tenant and service identities must stay distinct");
  static_assert(!std::is_same_v<TenantId, IsolationDomainId>, "tenant and domain identities must stay distinct");
  static_assert(!std::is_same_v<ServiceId, IsolationDomainId>, "service and domain identities must stay distinct");
  static_assert(!std::is_same_v<TenantId, PrincipalId>, "tenant and principal identities must stay distinct");
  static_assert(!std::is_same_v<PrincipalId, MetadataKey>, "principal and metadata key must stay distinct");
  static_assert(!std::is_convertible_v<TenantId, ServiceId>, "an identity must never convert to another kind");
  static_assert(!std::is_constructible_v<ServiceId, TenantId>, "an identity must never be built from another kind");
  static_assert(std::is_same_v<decltype(TenantId::create(std::declval<std::string_view>())), Result<TenantId>>);
  static_assert(std::is_same_v<decltype(ServiceId::create(std::declval<std::string_view>())), Result<ServiceId>>);
  static_assert(std::is_same_v<decltype(MetadataKey::create(std::declval<std::string_view>())), Result<MetadataKey>>);

  // The distinct types also carry distinct kind tokens, so a rendering of one
  // can never be mistaken for a rendering of another.
  TREG_CHECK(TenantId::create("acme").value().kind_token() !=
             ServiceId::create("acme").value().kind_token());
}

TREG_TEST(ids, identity_digest_domain_separation) {
  // The same text under six kinds must produce six different digests, because
  // the kind is part of the preimage.
  const ContentDigest tenant = tenant_id("shared").digest();
  const ContentDigest service = service_id("shared").digest();
  const ContentDigest domain = domain_id("shared").digest();
  const ContentDigest principal = principal_id("shared").digest();
  const ContentDigest source = unwrap(SourceId::create("shared"), "SourceId::create").digest();
  const ContentDigest key = metadata_key("shared").digest();

  TREG_CHECK(tenant != service);
  TREG_CHECK(tenant != domain);
  TREG_CHECK(tenant != principal);
  TREG_CHECK(tenant != source);
  TREG_CHECK(tenant != key);
  TREG_CHECK(service != domain);
  TREG_CHECK(service != principal);
  TREG_CHECK(service != source);
  TREG_CHECK(service != key);
  TREG_CHECK(domain != principal);
  TREG_CHECK(domain != source);
  TREG_CHECK(domain != key);
  TREG_CHECK(principal != source);
  TREG_CHECK(principal != key);
  TREG_CHECK(source != key);

  // A digest is a real digest, never the unset one, and it moves with the text.
  TREG_CHECK(!tenant.is_zero());
  TREG_CHECK(tenant != ContentDigest::zero());
  TREG_CHECK(tenant == tenant_id("shared").digest());
  TREG_CHECK(tenant != tenant_id("other").digest());
  TREG_CHECK_EQ(tenant.to_text().size(), static_cast<std::size_t>(64));
}

TREG_TEST(ids, idempotency_key_rules) {
  const std::string shortest(8, 'k');
  const std::string longest(64, 'k');
  const std::string too_short(7, 'k');
  const std::string too_long(65, 'k');

  TREG_CHECK(IdempotencyKey::create(shortest).has_value());
  TREG_CHECK(IdempotencyKey::create(longest).has_value());
  TREG_CHECK_CODE(IdempotencyKey::create(too_short), ErrorCode::IdempotencyKeyMalformed);
  TREG_CHECK_CODE(IdempotencyKey::create(too_long), ErrorCode::IdempotencyKeyMalformed);
  TREG_CHECK_CODE(IdempotencyKey::create(""), ErrorCode::IdempotencyKeyMalformed);

  // The key obeys the same charset and boundary rules as an identity token.
  TREG_CHECK_CODE(IdempotencyKey::create(".1234567"), ErrorCode::IdempotencyKeyMalformed);
  TREG_CHECK_CODE(IdempotencyKey::create("-1234567"), ErrorCode::IdempotencyKeyMalformed);
  TREG_CHECK_CODE(IdempotencyKey::create("1234567."), ErrorCode::IdempotencyKeyMalformed);
  TREG_CHECK_CODE(IdempotencyKey::create("1234567:"), ErrorCode::IdempotencyKeyMalformed);
  TREG_CHECK_CODE(IdempotencyKey::create("1234 567"), ErrorCode::IdempotencyKeyMalformed);
  TREG_CHECK_CODE(IdempotencyKey::create(bytes_of({'1', 0x00, '2', '3', '4', '5', '6', '7'})),
                  ErrorCode::IdempotencyKeyMalformed);
  TREG_CHECK(IdempotencyKey::create("req-0001.a_b:c").has_value());

  const IdempotencyKey key = idempotency_key("req-0001");
  TREG_CHECK_EQ(key.value(), std::string{"req-0001"});
  TREG_CHECK_EQ(key.to_text(), std::string{"req-0001"});
  TREG_CHECK(key == idempotency_key("req-0001"));
  TREG_CHECK(key != idempotency_key("req-0002"));
  TREG_CHECK(key < idempotency_key("req-0002"));
}

TREG_TEST(ids, tenancy_subject_tagging_and_text) {
  const TenancySubject tenant = TenancySubject::of_tenant(tenant_id("acme"));
  TREG_CHECK(tenant.is_tenant());
  TREG_CHECK(!tenant.is_service());
  TREG_CHECK(!tenant.is_isolation_domain());
  TREG_CHECK_EQ(tenant.kind(), SubjectKind::Tenant);
  TREG_CHECK_EQ(tenant.to_text(), std::string{"tenant:acme"});
  TREG_CHECK_EQ(tenant.identity_value(), std::string_view{"acme"});
  TREG_REQUIRE(tenant.tenant_if() != nullptr);
  TREG_CHECK_EQ(tenant.tenant_if()->value(), std::string{"acme"});
  TREG_CHECK(tenant.service_if() == nullptr);
  TREG_CHECK(tenant.isolation_domain_if() == nullptr);

  const TenancySubject service = TenancySubject::of_service(service_id("acme"));
  TREG_CHECK(service.is_service());
  TREG_CHECK_EQ(service.kind(), SubjectKind::Service);
  TREG_CHECK_EQ(service.to_text(), std::string{"service:acme"});
  TREG_REQUIRE(service.service_if() != nullptr);
  TREG_CHECK(service.tenant_if() == nullptr);
  TREG_CHECK(service.isolation_domain_if() == nullptr);

  const TenancySubject domain = TenancySubject::of_isolation_domain(domain_id("acme"));
  TREG_CHECK(domain.is_isolation_domain());
  TREG_CHECK_EQ(domain.kind(), SubjectKind::IsolationDomain);
  TREG_CHECK_EQ(domain.to_text(), std::string{"isolation_domain:acme"});
  TREG_REQUIRE(domain.isolation_domain_if() != nullptr);
  TREG_CHECK(domain.tenant_if() == nullptr);
  TREG_CHECK(domain.service_if() == nullptr);

  // The tag is part of the value: identical text under different kinds is not
  // the same subject.
  TREG_CHECK(tenant != service);
  TREG_CHECK(service != domain);
  TREG_CHECK(tenant != domain);
  TREG_CHECK(tenant.to_text() != service.to_text());
  TREG_CHECK(tenant == TenancySubject::of_tenant(tenant_id("acme")));

  // Ordering is the byte order of the canonical token, so a sorted listing
  // reads the way the text reads.
  TREG_CHECK(domain < service);
  TREG_CHECK(service < tenant);
  TREG_CHECK(TenancySubject::of_tenant(tenant_id("a")) < TenancySubject::of_tenant(tenant_id("b")));

  TREG_CHECK_EQ(to_token(SubjectKind::Unspecified), std::string_view{"unspecified"});
  TREG_CHECK_EQ(to_token(SubjectKind::Tenant), std::string_view{"tenant"});
  TREG_CHECK_EQ(to_token(SubjectKind::Service), std::string_view{"service"});
  TREG_CHECK_EQ(to_token(SubjectKind::IsolationDomain), std::string_view{"isolation_domain"});
  TREG_CHECK_EQ(to_token(static_cast<SubjectKind>(99)), std::string_view{});

  SubjectKind parsed = SubjectKind::Unspecified;
  TREG_CHECK(parse_subject_kind("tenant", parsed));
  TREG_CHECK_EQ(parsed, SubjectKind::Tenant);
  TREG_CHECK(parse_subject_kind("isolation_domain", parsed));
  TREG_CHECK_EQ(parsed, SubjectKind::IsolationDomain);
  TREG_CHECK(parse_subject_kind("unspecified", parsed));
  TREG_CHECK_EQ(parsed, SubjectKind::Unspecified);
  TREG_CHECK(!parse_subject_kind("Tenant", parsed));
  TREG_CHECK(!parse_subject_kind("", parsed));
  TREG_CHECK(!parse_subject_kind("tenancy", parsed));
}

TREG_TEST(ids, counter_advance_saturates_and_never_wraps) {
  TREG_CHECK_EQ(RegistryGeneration::initial().value(), static_cast<std::uint64_t>(0));
  TREG_CHECK(RegistryGeneration::initial().is_initial());
  TREG_CHECK_EQ(RegistryGeneration::initial().to_text(), std::string{"generation:0"});
  TREG_CHECK_EQ(RecordRevision::initial().to_text(), std::string{"revision:0"});
  TREG_CHECK_EQ(DomainGeneration::initial().to_text(), std::string{"domain_generation:0"});
  TREG_CHECK_EQ(ControlEpoch::initial().to_text(), std::string{"control_epoch:0"});
  TREG_CHECK_EQ(Incarnation::initial().to_text(), std::string{"incarnation:0"});
  TREG_CHECK_EQ(JournalSequence::initial().to_text(), std::string{"sequence:0"});
  TREG_CHECK(!RegistryGeneration::from_value(1).is_initial());
  TREG_CHECK_EQ(std::string_view{JournalSequence::initial().kind_token()}, std::string_view{"sequence"});

  TREG_CHECK_CODE(advance(RegistryGeneration::from_value(kCounterMaximum)), ErrorCode::CounterSaturated);
  TREG_CHECK_CODE(advance(RecordRevision::from_value(kCounterMaximum)), ErrorCode::CounterSaturated);
  TREG_CHECK_CODE(advance(DomainGeneration::from_value(kCounterMaximum)), ErrorCode::CounterSaturated);
  TREG_CHECK_CODE(advance(ControlEpoch::from_value(kCounterMaximum)), ErrorCode::CounterSaturated);
  TREG_CHECK_CODE(advance(JournalSequence::from_value(kCounterMaximum)), ErrorCode::CounterSaturated);

  // A saturated counter keeps its value; a refused advance never wraps it into
  // a small one that would make stale state look current.
  TREG_CHECK_EQ(RegistryGeneration::from_value(kCounterMaximum).value(), kCounterMaximum);
  TREG_CHECK_EQ(RecordRevision::from_value(kCounterMaximum).value(), kCounterMaximum);

  const Result<RegistryGeneration> next_generation = advance(RegistryGeneration::from_value(kCounterMaximum - 1));
  TREG_REQUIRE_OK(next_generation);
  TREG_CHECK_EQ(next_generation.value().value(), kCounterMaximum);
  TREG_CHECK_EQ(next_generation.value().to_text(), std::string{"generation:"} + std::to_string(kCounterMaximum));

  const Result<RecordRevision> next_revision = advance(RecordRevision::initial());
  TREG_REQUIRE_OK(next_revision);
  TREG_CHECK_EQ(next_revision.value().value(), static_cast<std::uint64_t>(1));
  const Result<DomainGeneration> next_domain = advance(DomainGeneration::initial());
  TREG_REQUIRE_OK(next_domain);
  TREG_CHECK_EQ(next_domain.value().value(), static_cast<std::uint64_t>(1));
  const Result<ControlEpoch> next_epoch = advance(ControlEpoch::initial());
  TREG_REQUIRE_OK(next_epoch);
  TREG_CHECK_EQ(next_epoch.value().value(), static_cast<std::uint64_t>(1));
  const Result<JournalSequence> next_sequence = advance(JournalSequence::initial());
  TREG_REQUIRE_OK(next_sequence);
  TREG_CHECK_EQ(next_sequence.value().value(), static_cast<std::uint64_t>(1));

  TREG_CHECK_EQ(RegistryGeneration::from_value(7).value(), static_cast<std::uint64_t>(7));
  TREG_CHECK(RegistryGeneration::from_value(7) == RegistryGeneration::from_value(7));
  TREG_CHECK(RegistryGeneration::from_value(7) < RegistryGeneration::from_value(8));
}

TREG_TEST(ids, text_field_validation) {
  const Result<std::string> accepted = validate_text_field("hello world", 64, "display name");
  TREG_REQUIRE_OK(accepted);
  TREG_CHECK_EQ(accepted.value(), std::string{"hello world"});

  // Empty is a missing value wearing a value's clothes, so it is refused.
  TREG_CHECK_CODE(validate_text_field("", 64, "display name"), ErrorCode::InvalidTextForm);
  TREG_CHECK_CODE(validate_text_field("01234567890", 10, "display name"), ErrorCode::InvalidTextForm);
  TREG_CHECK(validate_text_field("0123456789", 10, "display name").has_value());
  TREG_CHECK_CODE(validate_text_field("line\nbreak", 64, "display name"), ErrorCode::InvalidTextForm);
  TREG_CHECK_CODE(validate_text_field(bytes_of({'a', 0x7F, 'b'}), 64, "display name"),
                  ErrorCode::InvalidTextForm);
  TREG_CHECK_CODE(validate_text_field(bytes_of({0x61, 0xC3, 0x28}), 64, "display name"), ErrorCode::InvalidUtf8);

  // The bound is a byte bound: a two byte code point does not fit a one byte
  // field even though it is one character.
  const Result<std::string> multibyte = validate_text_field(bytes_of({0xC3, 0xA9}), 2, "display name");
  TREG_REQUIRE_OK(multibyte);
  TREG_CHECK_EQ(multibyte.value().size(), static_cast<std::size_t>(2));
  TREG_CHECK_CODE(validate_text_field(bytes_of({0xC3, 0xA9}), 1, "display name"), ErrorCode::InvalidTextForm);
}

}  // namespace treg_test
