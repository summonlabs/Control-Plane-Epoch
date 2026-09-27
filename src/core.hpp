// Control Plane Epoch 1.0.0 - Summon Software Labs
// Internal implementation of the authority state machine. Not installed.
//
// One AuthorityCore owns one durable store and one non-recursive mutex. All
// mutation is plan -> validate -> apply to a copy -> commit durably -> adopt the
// copy, so a rejected or failed command can never leave partially applied state.
#pragma once

#include <filesystem>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

#include "control_plane_epoch/authority.hpp"
#include "control_plane_epoch/commands.hpp"
#include "control_plane_epoch/epoch.hpp"
#include "control_plane_epoch/error.hpp"
#include "control_plane_epoch/incarnation.hpp"
#include "control_plane_epoch/inspection.hpp"
#include "control_plane_epoch/provenance.hpp"
#include "control_plane_epoch/recovery.hpp"
#include "control_plane_epoch/store.hpp"
#include "control_plane_epoch/transition.hpp"

#include "authority_store.hpp"
#include "records.hpp"

namespace dccp::epoch::detail {

class AuthorityCore {
 public:
  explicit AuthorityCore(const StoreOpenOptions& options);
  ~AuthorityCore();

  AuthorityCore(const AuthorityCore&) = delete;
  AuthorityCore& operator=(const AuthorityCore&) = delete;
  AuthorityCore(AuthorityCore&&) = delete;
  AuthorityCore& operator=(AuthorityCore&&) = delete;

  [[nodiscard]] const RecoveryReport& recovery() const;
  [[nodiscard]] bool initialized() const;
  [[nodiscard]] bool closed() const noexcept;
  void close() noexcept;

  [[nodiscard]] Status initialize(InitializeDomainRequest request);

  [[nodiscard]] AuthorityStatus status() const;
  [[nodiscard]] AuthorityAccounting accounting() const;
  [[nodiscard]] Epoch current_epoch() const;

  /// Report of the most recent successful durable commit, if any. Lets a caller
  /// observe the generation, epoch, and digest that were published without
  /// handling raw persistence structures.
  [[nodiscard]] std::optional<DurableCommitReport> last_commit() const;

  [[nodiscard]] Result<ControllerRegistration> register_controller(RegisterControllerRequest request);
  [[nodiscard]] Result<AuthorityGrantView> acquire_authority(AcquireAuthorityRequest request);
  [[nodiscard]] Result<EpochTransitionRecord> advance_epoch(AdvanceEpochRequest request);
  [[nodiscard]] Result<RevocationRecord> revoke_authority(RevokeAuthorityRequest request);

  [[nodiscard]] ValidationOutcome validate_mutation(const MutationAuthority& authority, const ScopeName& scope);
  [[nodiscard]] ValidationOutcome validate_observation(const ObservationAuthority& authority, const ScopeName& scope);
  [[nodiscard]] Result<RecoveryQualification> qualify_recovered_state(const RecoveredStateClaim& claim);

  [[nodiscard]] Result<EpochHistoryPage> history(const HistoryQuery& query) const;
  [[nodiscard]] Result<RevocationPage> revocations(const RevocationQuery& query) const;
  [[nodiscard]] Result<ControllerPage> controllers(const ControllerQuery& query) const;
  [[nodiscard]] Result<GrantPage> grants(const GrantQuery& query) const;

  [[nodiscard]] Result<ControllerRecord> controller_record(const ControllerId& controller) const;
  [[nodiscard]] Result<AuthorityGrantRecord> grant_record(GrantId grant_id) const;

  void write_snapshot_artifact(const std::filesystem::path& path) const;

 private:
  // Helpers. Every one of them requires the mutex to be held.
  void require_open() const;
  void require_write(const char* operation) const;
  void require_domain() const;

  [[nodiscard]] const AuthorityImage& image() const noexcept { return store_->image(); }

  [[nodiscard]] static const ControllerData* find_controller(const AuthorityImage& image, std::string_view controller);
  [[nodiscard]] static ControllerData* find_controller(AuthorityImage& image, std::string_view controller);
  [[nodiscard]] static const GrantData* find_grant(const AuthorityImage& image, std::uint64_t grant_id);
  [[nodiscard]] static GrantData* find_grant(AuthorityImage& image, std::uint64_t grant_id);
  [[nodiscard]] static bool scope_declared(const AuthorityImage& image, std::string_view scope);
  [[nodiscard]] static std::uint64_t live_grant_count(const AuthorityImage& image);

  /// Reserves the next position in the domain's global mutation ledger. The
  /// returned sequence is the value recorded in provenance; the counter itself
  /// advances as a side effect, so the result is normally consumed by name.
  static std::uint64_t allocate_sequence(AuthorityImage& image);
  [[nodiscard]] static Sha256Digest transition_chain_head(const AuthorityImage& image);
  [[nodiscard]] static Sha256Digest revocation_chain_head(const AuthorityImage& image);

  template <class Token>
  [[nodiscard]] ValidationOutcome validate_token(const AuthorityImage& image, const Token& token,
                                                 const ScopeName& scope) const;

  [[nodiscard]] ValidationOutcome validate_incarnation(const AuthorityImage& image, const ControllerId& controller,
                                                       const ControllerIncarnationId& incarnation) const;

  /// Idempotency: returns the recorded result blob when the key was already
  /// used for an identical command, and rejects a key reused for a different
  /// command.
  [[nodiscard]] Result<std::optional<std::vector<std::byte>>> lookup_idempotent(
      const AuthorityImage& image, const IdempotencyKey& key, const Sha256Digest& command_digest) const;
  void record_idempotent(AuthorityImage& image, const IdempotencyKey& key, const Sha256Digest& command_digest,
                         std::vector<std::byte> result_blob);

  static void trim_transitions(AuthorityImage& image);
  static void trim_revocations(AuthorityImage& image);
  static void trim_idempotency(AuthorityImage& image);

  [[nodiscard]] static ProvenanceData make_provenance_data(const AuthorityImage& image,
                                                           const ProvenanceInput& input, std::uint64_t sequence);
  [[nodiscard]] static ProvenanceData make_provenance_data(const AuthorityImage& image,
                                                           const ProvenanceInput& input, std::uint64_t sequence,
                                                           std::uint64_t epoch);
  [[nodiscard]] static std::optional<Explanation> validate_provenance_input(const ProvenanceInput& input,
                                                                           std::string_view what);

  /// Applies a command image transactionally: commits it durably and only then
  /// adopts it. Throws EpochError when the commit fails.
  void commit_image(AuthorityImage image);

  mutable std::mutex mutex_;
  std::unique_ptr<AuthorityStore> store_;
  std::optional<DurableCommitReport> last_commit_;
};

}  // namespace dccp::epoch::detail
