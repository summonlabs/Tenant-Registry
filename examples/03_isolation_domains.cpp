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

// Example 03: isolation domains.
//
// Two domains are declared with different classes, and tenants and a service
// are bound into them. The transcript shows that membership is declared and
// queryable, that isolation is never inferred from anything else, and that a
// membership write addressed to a domain generation that has moved on is
// refused.

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

#include "support.hpp"

namespace tr = tenant_registry;
using namespace treg_examples;

int main() {
  StepPrinter step{"03 isolation domains"};

  step("open an ephemeral registry");
  tr::TenantRegistry registry =
      required(tr::TenantRegistry::open_ephemeral(ephemeral_options()), "open an ephemeral registry");

  step("declare isolation domain zone-a, class fault_containment");
  const tr::IsolationDomainId zone_a = domain("zone-a");
  const tr::CreateIsolationDomainOutcome zone_a_declared = required(
      registry.create_isolation_domain(tr::CreateIsolationDomainRequest{
          context(registry.generation()), zone_a, tr::IsolationClass::FaultContainment,
          std::string{"Zone A"}, tr::TenancyMetadata{}}),
      "declare isolation domain zone-a");
  step.note(field("identity", zone_a_declared.record.id.to_text()) + " " +
            field("class", tr::to_token(zone_a_declared.record.isolation_class)) + " " +
            field("state", tr::to_token(zone_a_declared.record.state)) + " " +
            field("membership_generation", zone_a_declared.record.membership_generation.value()));

  step("declare isolation domain zone-b, class regulatory");
  const tr::IsolationDomainId zone_b = domain("zone-b");
  const tr::CreateIsolationDomainOutcome zone_b_declared = required(
      registry.create_isolation_domain(tr::CreateIsolationDomainRequest{
          context(registry.generation()), zone_b, tr::IsolationClass::Regulatory,
          std::string{"Zone B"}, tr::TenancyMetadata{}}),
      "declare isolation domain zone-b");
  step.note(field("identity", zone_b_declared.record.id.to_text()) + " " +
            field("class", tr::to_token(zone_b_declared.record.isolation_class)) + " " +
            field("state", tr::to_token(zone_b_declared.record.state)) + " " +
            field("membership_generation", zone_b_declared.record.membership_generation.value()));

  step("admit both domains: declared -> active");
  const auto admit = [&registry](tr::TenancySubject member) {
    const tr::SubjectRecord record =
        required(registry.find_subject(member), "read the subject to admit");
    required_ok(registry.transition_subject(
                    tr::TransitionSubjectRequest{context(registry.generation()), member,
                                                 tr::subject_revision(record), tr::LifecycleState::Active}),
                "admit a subject");
  };
  admit(tr::TenancySubject::of_isolation_domain(zone_a));
  admit(tr::TenancySubject::of_isolation_domain(zone_b));
  step.note(field("generation", registry.generation().value()) + " " +
            field("state", tr::to_token(required(registry.find_isolation_domain(zone_a), "read zone-a").state)));

  step("declare and admit tenant acme");
  const tr::TenantId acme = tenant("acme");
  const tr::CreateTenantOutcome acme_declared = required(
      registry.create_tenant(tr::CreateTenantRequest{context(registry.generation()), acme,
                                                     std::string{"Acme Facility"}, std::nullopt,
                                                     tr::TenancyMetadata{}}),
      "declare tenant acme");
  required_ok(registry.transition_subject(tr::TransitionSubjectRequest{context(registry.generation()),
                                                                      tr::TenancySubject::of_tenant(acme),
                                                                      acme_declared.record.revision,
                                                                      tr::LifecycleState::Active}),
              "admit tenant acme");

  step("declare and admit tenant beta");
  const tr::TenantId beta = tenant("beta");
  const tr::CreateTenantOutcome beta_declared = required(
      registry.create_tenant(tr::CreateTenantRequest{context(registry.generation()), beta,
                                                     std::string{"Beta Facility"}, std::nullopt,
                                                     tr::TenancyMetadata{}}),
      "declare tenant beta");
  required_ok(registry.transition_subject(tr::TransitionSubjectRequest{context(registry.generation()),
                                                                      tr::TenancySubject::of_tenant(beta),
                                                                      beta_declared.record.revision,
                                                                      tr::LifecycleState::Active}),
              "admit tenant beta");

  step("read the membership generation of zone-a before changing its membership");
  const tr::IsolationDomainRecord zone_a_before =
      required(registry.find_isolation_domain(zone_a), "read isolation domain zone-a");
  step.note(field("domain", zone_a_before.id.to_text()) + " " +
            field("membership_generation", zone_a_before.membership_generation.value()) + " " +
            field("revision", zone_a_before.revision.value()));

  step("bind tenant acme into zone-a as its primary domain");
  const tr::PutIsolationMembershipOutcome acme_membership = required(
      registry.put_isolation_membership(tr::PutIsolationMembershipRequest{
          context(registry.generation()), tr::TenancySubject::of_tenant(acme), zone_a,
          tr::MembershipRole::Primary, tr::MembershipState::Bound,
          zone_a_before.membership_generation, std::nullopt}),
      "bind tenant acme into zone-a");
  step.note(field("membership", acme_membership.membership.natural_key()) + " " +
            field("role", tr::to_token(acme_membership.membership.role)) + " " +
            field("state", tr::to_token(acme_membership.membership.state)) + " " +
            field("revision", acme_membership.membership.revision.value()) + " " +
            field("domain_generation",
                  movement(zone_a_before.membership_generation.value(),
                           acme_membership.domain_generation.value())));

  step("bind tenant beta into zone-a as a secondary member");
  const tr::IsolationDomainRecord zone_a_after =
      required(registry.find_isolation_domain(zone_a), "read isolation domain zone-a");
  const tr::PutIsolationMembershipOutcome beta_membership = required(
      registry.put_isolation_membership(tr::PutIsolationMembershipRequest{
          context(registry.generation()), tr::TenancySubject::of_tenant(beta), zone_a,
          tr::MembershipRole::Secondary, tr::MembershipState::Bound,
          zone_a_after.membership_generation, std::nullopt}),
      "bind tenant beta into zone-a");
  step.note(field("membership", beta_membership.membership.natural_key()) + " " +
            field("role", tr::to_token(beta_membership.membership.role)) + " " +
            field("state", tr::to_token(beta_membership.membership.state)) + " " +
            field("domain_generation",
                  movement(zone_a_after.membership_generation.value(),
                           beta_membership.domain_generation.value())));

  step("ask which domains tenant acme is in force in");
  const std::vector<tr::IsolationDomainId> acme_domains =
      required(registry.isolation_domains_of(tr::TenancySubject::of_tenant(acme)),
               "list the domains of tenant acme");
  step.note(field("domains", static_cast<std::uint64_t>(acme_domains.size())));
  for (const tr::IsolationDomainId& listed : acme_domains) {
    step.note("domain " + listed.to_text());
  }

  step("ask who is in force in zone-a");
  const std::vector<tr::TenancySubject> zone_a_members =
      required(registry.members_of(zone_a, 16), "list the members of zone-a");
  step.note(field("members", static_cast<std::uint64_t>(zone_a_members.size())));
  for (const tr::TenancySubject& member : zone_a_members) {
    step.note("member " + member.to_text());
  }

  step("ask who is in force in zone-b, which nothing has been bound into");
  const std::vector<tr::TenancySubject> zone_b_members =
      required(registry.members_of(zone_b, 16), "list the members of zone-b");
  step.note(field("members", static_cast<std::uint64_t>(zone_b_members.size())) + " " +
            field("note", "membership of zone-a is not membership of zone-b"));

  step("try to make zone-b a member of zone-a");
  const tr::Result<tr::PutIsolationMembershipOutcome> domain_member =
      registry.put_isolation_membership(tr::PutIsolationMembershipRequest{
          context(registry.generation()), subject("isolation_domain:zone-b"), zone_a,
          tr::MembershipRole::Secondary, tr::MembershipState::Bound,
          beta_membership.domain_generation, std::nullopt});
  if (domain_member.has_value()) {
    fail("an isolation domain was accepted as a member of another isolation domain");
  }
  step.note("refused: " + refusal_text(domain_member.error()));

  step("write a membership against a domain generation that has moved on");
  const tr::Result<tr::PutIsolationMembershipOutcome> stale = registry.put_isolation_membership(
      tr::PutIsolationMembershipRequest{context(registry.generation()), tr::TenancySubject::of_tenant(beta), zone_a,
                                        tr::MembershipRole::Secondary, tr::MembershipState::Bound,
                                        tr::DomainGeneration::initial(), std::nullopt});
  if (stale.has_value()) {
    fail("a membership write against a stale domain generation was accepted");
  }
  step.note("refused: " + refusal_text(stale.error()));

  step("read zone-a through a cached membership generation that is also stale");
  const tr::Result<tr::IsolationDomainRecord> fenced =
      registry.find_isolation_domain(zone_a, tr::DomainGeneration::from_value(1));
  if (fenced.has_value()) {
    fail("a cached membership generation that had moved on was accepted");
  }
  step.note("refused: " + refusal_text(fenced.error()));

  step("list the memberships of both domains");
  const tr::Page<tr::MembershipSummary> listed = required(
      registry.list_isolation_memberships(tr::MembershipQuery{}), "list isolation memberships");
  step.note(field("total_matched", static_cast<std::uint64_t>(listed.total_matched)) + " " +
            field("truncated", yes_no(listed.truncated)));
  for (const tr::MembershipSummary& membership : listed.items) {
    step.note(field("membership", membership.subject.to_text() + "|" + membership.domain.to_text()) + " " +
              field("role", tr::to_token(membership.role)) + " " +
              field("state", tr::to_token(membership.state)) + " " +
              field("revision", membership.revision.value()));
  }

  return 0;
}
