defmodule AttestoPhoenix.AuthorizationServer.AuthorizationCodeCompletionTest do
  @moduledoc """
  Transaction-boundary coverage for authorization-code completion.

  These tests run against the package's real Ecto code and refresh stores on an
  unboxed SQL sandbox connection. That makes the host callback's
  `Repo.transaction/1` the actual transaction boundary: redemption commits
  before the callback, while every continuation write either commits together
  or rolls back together.
  """

  use ExUnit.Case, async: false

  import Ecto.Query
  import ExUnit.CaptureLog

  alias AttestoPhoenix.AuthorizationCodePrivateContext
  alias AttestoPhoenix.AuthorizationServer.Token
  alias AttestoPhoenix.AuthorizationServer.Token.Request
  alias AttestoPhoenix.{Config, OAuthError, TestRepo}
  alias AttestoPhoenix.Schema.{Authorization, LogoutSession, RefreshToken}
  alias AttestoPhoenix.Store.{EctoCodeStore, EctoLogoutSessionStore, EctoRefreshStore}
  alias Ecto.Adapters.SQL.Sandbox

  @moduletag :ecto

  @signing_pem JOSE.JWK.generate_key({:rsa, 2048}) |> JOSE.JWK.to_pem() |> elem(1)
  @code_verifier "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
  @code_challenge "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
  @redirect_uri "https://client.example/cb"
  @client %{id: "client-1", public?: false}
  @client_kind Attesto.PrincipalKind.new("client", "oc_", required_claims: [{"client_id", :non_empty_string}])

  defmodule Keystore do
    @moduledoc false
    @behaviour Attesto.Keystore

    @impl true
    def signing_pem do
      :attesto_phoenix
      |> Application.fetch_env!(__MODULE__)
      |> Keyword.fetch!(:signing_pem)
    end

    @impl true
    def verification_pems, do: [signing_pem()]
  end

  defmodule CompletionCodeStore do
    @moduledoc false
    @behaviour Attesto.CodeStore

    @impl true
    def put(record), do: EctoCodeStore.put(record)

    @impl true
    def take(code_hash), do: EctoCodeStore.take(code_hash)

    @impl true
    def get(code_hash), do: EctoCodeStore.get(code_hash)

    @impl true
    def mark_consumed(code_hash, meta) do
      notify(:code_finalization)
      EctoCodeStore.mark_consumed(code_hash, meta)
    end

    def record_access_token(family_id, jti, expires_at) do
      notify({:access_jti, family_id, jti, expires_at})
      EctoCodeStore.record_access_token(family_id, jti, expires_at)
    end

    defp notify(step) do
      if pid = Process.get(:authorization_code_completion_test_pid) do
        send(pid, {:completion_step, step, Process.get(:authorization_code_completion_active) == true})
      end
    end
  end

  defmodule CompletionRefreshStore do
    @moduledoc false
    @behaviour Attesto.RefreshStore

    @impl true
    def insert(record) do
      notify({:refresh_insert, record.family_id, record.generation})
      EctoRefreshStore.insert(record)
    end

    @impl true
    def get(token_hash), do: EctoRefreshStore.get(token_hash)

    @impl true
    def consume(token_hash, opts), do: EctoRefreshStore.consume(token_hash, opts)

    @impl true
    def remember_successor(token_hash, successor, opts),
      do: EctoRefreshStore.remember_successor(token_hash, successor, opts)

    @impl true
    def revoke_family(family_id), do: EctoRefreshStore.revoke_family(family_id)

    defp notify(step) do
      if pid = Process.get(:authorization_code_completion_test_pid) do
        send(pid, {:completion_step, step, Process.get(:authorization_code_completion_active) == true})
      end
    end
  end

  defmodule FailingRefreshStore do
    @moduledoc false
    @behaviour Attesto.RefreshStore

    @impl true
    def insert(record) do
      notify({:refresh_insert_failed, record.family_id, record.generation})
      {:error, :family_revoked}
    end

    @impl true
    def get(token_hash), do: EctoRefreshStore.get(token_hash)

    @impl true
    def consume(token_hash, opts), do: EctoRefreshStore.consume(token_hash, opts)

    @impl true
    def remember_successor(token_hash, successor, opts),
      do: EctoRefreshStore.remember_successor(token_hash, successor, opts)

    @impl true
    def revoke_family(family_id), do: EctoRefreshStore.revoke_family(family_id)

    defp notify(step) do
      if pid = Process.get(:authorization_code_completion_test_pid) do
        send(pid, {:completion_step, step, Process.get(:authorization_code_completion_active) == true})
      end
    end
  end

  defmodule FailingAccessJTIStore do
    @moduledoc false
    @behaviour Attesto.CodeStore

    @impl true
    defdelegate put(record), to: EctoCodeStore

    @impl true
    defdelegate take(code_hash), to: EctoCodeStore

    @impl true
    defdelegate get(code_hash), to: EctoCodeStore

    @impl true
    defdelegate mark_consumed(code_hash, meta), to: EctoCodeStore

    def record_access_token(family_id, _jti, _expires_at) do
      logout_count = TestRepo.aggregate(LogoutSession, :count)
      notify({:access_jti_failed, family_id, logout_count})
      raise "injected access JTI failure"
    end

    defp notify(step) do
      if pid = Process.get(:authorization_code_completion_test_pid) do
        send(pid, {:completion_step, step, Process.get(:authorization_code_completion_active) == true})
      end
    end
  end

  defmodule FailingFinalizationCodeStore do
    @moduledoc false
    @behaviour Attesto.CodeStore

    @impl true
    defdelegate put(record), to: EctoCodeStore

    @impl true
    defdelegate take(code_hash), to: EctoCodeStore

    @impl true
    defdelegate get(code_hash), to: EctoCodeStore

    def record_access_token(family_id, jti, expires_at) do
      EctoCodeStore.record_access_token(family_id, jti, expires_at)
    end

    @impl true
    def mark_consumed(code_hash, _meta) do
      row = TestRepo.get_by!(Authorization, code_hash: code_hash)

      notify({
        :finalization_failed,
        is_binary(row.access_token_jti),
        TestRepo.aggregate(RefreshToken, :count),
        TestRepo.aggregate(LogoutSession, :count)
      })

      raise "injected code finalization failure"
    end

    defp notify(step) do
      if pid = Process.get(:authorization_code_completion_test_pid) do
        send(pid, {:completion_step, step, Process.get(:authorization_code_completion_active) == true})
      end
    end
  end

  defmodule AgentCodeStore do
    @moduledoc false
    @behaviour Attesto.CodeStore

    def child_spec(_opts) do
      %{id: __MODULE__, start: {__MODULE__, :start_link, [[]]}}
    end

    def start_link(_opts), do: Agent.start_link(fn -> %{} end, name: __MODULE__)

    @impl true
    def put(record) do
      entry = %{record: record, consumed: false, consumed_success: false, meta: nil, access_token_jti: nil}
      Agent.update(__MODULE__, &Map.put(&1, record.code_hash, entry))
      :ok
    end

    @impl true
    def get(code_hash) do
      Agent.get(__MODULE__, fn state ->
        case Map.get(state, code_hash) do
          %{consumed: false, record: record} -> {:ok, record}
          _other -> :error
        end
      end)
    end

    @impl true
    def take(code_hash) do
      Agent.get_and_update(__MODULE__, fn state ->
        case Map.get(state, code_hash) do
          %{consumed: false, record: record} = entry ->
            {{:ok, record}, Map.put(state, code_hash, %{entry | consumed: true})}

          %{consumed_success: true, meta: meta} ->
            {{:error, :consumed, meta}, state}

          _other ->
            {:error, state}
        end
      end)
    end

    @impl true
    def mark_consumed(code_hash, meta) do
      Agent.update(__MODULE__, fn state ->
        Map.update!(state, code_hash, &%{&1 | consumed_success: true, meta: meta})
      end)

      :ok
    end

    def record_access_token(family_id, jti, _expires_at) do
      Agent.update(__MODULE__, fn state ->
        Map.new(state, &put_access_token_jti(&1, family_id, jti))
      end)

      :ok
    end

    def entry(code) do
      Agent.get(__MODULE__, &Map.fetch!(&1, Attesto.Secret.hash(code)))
    end

    defp put_access_token_jti({code_hash, %{record: %{data: %{family_id: family_id}}} = entry}, family_id, jti),
      do: {code_hash, %{entry | access_token_jti: jti}}

    defp put_access_token_jti(entry, _family_id, _jti), do: entry
  end

  setup do
    owner = Sandbox.start_owner!(TestRepo, sandbox: false)
    start_supervised!(AgentCodeStore)

    TestRepo.delete_all(LogoutSession)
    TestRepo.delete_all(RefreshToken)
    TestRepo.delete_all(Authorization)

    Application.put_env(:attesto_phoenix, __MODULE__.Keystore, signing_pem: @signing_pem)
    Process.put(:authorization_code_completion_test_pid, self())

    on_exit(fn ->
      :ok = Sandbox.allow(TestRepo, owner, self())
      TestRepo.delete_all(LogoutSession)
      TestRepo.delete_all(RefreshToken)
      TestRepo.delete_all(Authorization)
      Sandbox.stop_owner(owner)
      Application.delete_env(:attesto_phoenix, __MODULE__.Keystore)
    end)

    :ok
  end

  test "the absent callback preserves direct completion and all writes" do
    family_id = "family-default"
    code = issue_code(family_id)
    config = config()

    assert Config.authorization_code_completion_fun(config) == nil
    assert {:ok, response, _events} = Token.issue(config, code_request(config, code))
    assert is_binary(response.access_token)
    assert is_binary(response.refresh_token)

    row = authorization!(family_id)
    assert row.consumed_at
    assert row.consumed_success
    assert row.access_token_jti == claim!(response.access_token, "jti")

    assert %RefreshToken{family_id: ^family_id, generation: 0} =
             TestRepo.one!(from r in RefreshToken, where: r.family_id == ^family_id)
  end

  test "the callback receives only stable identifiers and spans every completion step" do
    test_pid = self()
    family_id = "family-transaction"
    private_context = %{"security_epoch" => 42}
    code = issue_code(family_id, ["openid", "offline_access"], private_context: private_context)

    config =
      config(
        authorization_code_completion: transactional_completion(test_pid),
        build_principal: fn client, subject, scope ->
          send(test_pid, {:completion_step, :build_principal, completion_active?()})
          principal(client, subject, scope)
        end,
        build_id_token_claims: fn _client, _subject, _scope, _requested ->
          send(test_pid, {:completion_step, :build_id_token_claims, completion_active?()})
          %{}
        end
      )

    assert {:ok, response, _events} = Token.issue(config, code_request(config, code))
    assert is_binary(response.access_token)
    assert is_binary(response.id_token)
    assert is_binary(response.refresh_token)

    assert_receive {:completion_context,
                    %{
                      client_id: "client-1",
                      subject: "oc_user-1",
                      family_id: ^family_id,
                      private_context: ^private_context
                    } = context}

    assert map_size(context) == 4
    assert_receive {:completion_step, :transaction_started, true}
    assert_receive {:completion_step, :build_principal, true}
    assert_receive {:completion_step, :build_id_token_claims, true}
    assert_receive {:completion_step, {:access_jti, ^family_id, jti, expires_at}, true}
    assert is_binary(jti)
    assert is_integer(expires_at)
    assert_receive {:completion_step, {:refresh_insert, ^family_id, 0}, true}
    assert_receive {:completion_step, :code_finalization, true}
    assert_receive :authorization_code_completion_committed
  end

  test "a host rollback after the continuation leaves no JTI, refresh, or finalization writes" do
    family_id = "family-host-rollback"
    private_context = %{"security_epoch" => 7}
    code = issue_code(family_id, ["offline_access"], private_context: private_context)

    callback = fn context, continuation ->
      assert context.family_id == family_id
      assert context.private_context == private_context

      assert {:error, :host_policy_changed} =
               TestRepo.transaction(fn ->
                 Process.put(:authorization_code_completion_active, true)

                 try do
                   assert {:ok, _response, _events} = continuation.()

                   inside = authorization!(family_id)
                   assert inside.access_token_jti
                   assert inside.consumed_success
                   assert TestRepo.aggregate(from(r in RefreshToken, where: r.family_id == ^family_id), :count) == 1

                   TestRepo.rollback(:host_policy_changed)
                 after
                   Process.delete(:authorization_code_completion_active)
                 end
               end)

      {:error, :host_policy_changed}
    end

    config = config(authorization_code_completion: callback)

    capture_log(fn ->
      assert {:error, %OAuthError{error: :invalid_request}, _events} =
               Token.issue(config, code_request(config, code))
    end)

    assert_spent_without_completion(family_id)
  end

  test "private context is completion-only and leaves OIDC and token claims unchanged" do
    test_pid = self()
    family_id = "family-private-nondisclosure"
    private_context = %{"mobile_auth_security_epoch" => 42, "marker" => "never-token-visible"}

    code =
      issue_code(family_id, ["openid", "offline_access"],
        private_context: private_context,
        claims: %{
          "nonce" => "oidc-nonce",
          "auth_time" => 1_700_000_000,
          "acr" => "urn:example:loa:2",
          "amr" => ["pwd"]
        }
      )

    config =
      config(
        authorization_code_completion: fn context, continuation ->
          send(test_pid, {:private_context_at_completion, context.private_context})
          continuation.()
        end
      )

    assert {:ok, response, _events} = Token.issue(config, code_request(config, code))
    assert_receive {:private_context_at_completion, ^private_context}

    access_claims = claims!(response.access_token)
    id_claims = claims!(response.id_token)

    refute Map.has_key?(access_claims, "mobile_auth_security_epoch")
    refute Map.has_key?(access_claims, "marker")
    refute Map.has_key?(access_claims, "private_context")
    refute Map.has_key?(id_claims, "mobile_auth_security_epoch")
    refute Map.has_key?(id_claims, "marker")
    refute Map.has_key?(id_claims, "private_context")
    assert id_claims["nonce"] == "oidc-nonce"
    assert id_claims["auth_time"] == 1_700_000_000
    assert id_claims["acr"] == "urn:example:loa:2"
    assert id_claims["amr"] == ["pwd"]
  end

  test "a callback refusal runs before principal construction and leaves completion empty" do
    test_pid = self()
    family_id = "family-refused"
    code = issue_code(family_id)

    config =
      config(
        authorization_code_completion: fn context, _continuation ->
          send(test_pid, {:completion_refused, context})
          {:error, :subject_revoked}
        end,
        build_principal: fn client, subject, scope ->
          send(test_pid, :build_principal_invoked)
          principal(client, subject, scope)
        end
      )

    capture_log(fn ->
      assert {:error, %OAuthError{error: :invalid_request}, _events} =
               Token.issue(config, code_request(config, code))
    end)

    assert_receive {:completion_refused,
                    %{
                      client_id: "client-1",
                      subject: "oc_user-1",
                      family_id: ^family_id,
                      private_context: nil
                    }}

    refute_received :build_principal_invoked
    assert_spent_without_completion(family_id)
  end

  test "a downstream refresh failure rolls the earlier JTI write back and does not finalize" do
    family_id = "family-refresh-failure"
    code = issue_code(family_id)

    config =
      config(
        refresh_store: FailingRefreshStore,
        authorization_code_completion: transactional_completion(self())
      )

    capture_log(fn ->
      assert {:error, %OAuthError{error: :invalid_request}, _events} =
               Token.issue(config, code_request(config, code))
    end)

    assert_receive {:completion_step, {:access_jti, ^family_id, _jti, _expires_at}, true}
    assert_receive {:completion_step, {:refresh_insert_failed, ^family_id, 0}, true}
    assert_receive :authorization_code_completion_rolled_back
    refute_received {:completion_step, :code_finalization, _active}
    assert_spent_without_completion(family_id)
  end

  test "the continuation is one-shot within the owner process" do
    family_id = "family-double-call"
    code = issue_code(family_id)
    test_pid = self()

    callback = fn _context, continuation ->
      assert {:error, {:second_call, %OAuthError{} = second_call_error}} =
               TestRepo.transaction(fn ->
                 Process.put(:authorization_code_completion_active, true)

                 try do
                   assert {:ok, _response, _events} = continuation.()
                   assert {:error, %OAuthError{} = error} = continuation.()
                   TestRepo.rollback({:second_call, error})
                 after
                   Process.delete(:authorization_code_completion_active)
                 end
               end)

      {:error, second_call_error}
    end

    config =
      config(
        authorization_code_completion: callback,
        build_principal: fn client, subject, scope ->
          send(test_pid, :guarded_build_principal)
          principal(client, subject, scope)
        end
      )

    assert {:error, %OAuthError{error: :invalid_request}, _events} =
             Token.issue(config, code_request(config, code))

    assert_receive :guarded_build_principal
    refute_receive :guarded_build_principal
    assert_receive {:completion_step, {:access_jti, ^family_id, _jti, _expires_at}, true}
    assert_receive {:completion_step, {:refresh_insert, ^family_id, 0}, true}
    assert_receive {:completion_step, :code_finalization, true}
    assert_spent_without_completion(family_id)
  end

  test "an escaped continuation is closed when the callback returns" do
    family_id = "family-escaped"
    code = issue_code(family_id)

    config =
      config(
        authorization_code_completion: fn _context, continuation ->
          send(self(), {:escaped_continuation, continuation})
          {:error, :host_declined}
        end,
        build_principal: fn _client, _subject, _scope ->
          flunk("an escaped continuation must not build a principal")
        end
      )

    capture_log(fn ->
      assert {:error, %OAuthError{error: :invalid_request}, _events} =
               Token.issue(config, code_request(config, code))
    end)

    assert_receive {:escaped_continuation, escaped}
    assert {:error, %OAuthError{error: :invalid_request}} = escaped.()
    assert_spent_without_completion(family_id)
  end

  test "a cross-process continuation invocation is rejected before completion" do
    family_id = "family-cross-process"
    code = issue_code(family_id)

    config =
      config(
        authorization_code_completion: fn _context, continuation ->
          Task.async(continuation) |> Task.await()
        end,
        build_principal: fn _client, _subject, _scope ->
          flunk("a cross-process continuation must not build a principal")
        end
      )

    assert {:error, %OAuthError{error: :invalid_request}, _events} =
             Token.issue(config, code_request(config, code))

    assert_spent_without_completion(family_id)
  end

  test "an invalid callback result is normalized without completion writes" do
    family_id = "family-invalid-callback-result"
    code = issue_code(family_id)
    config = config(authorization_code_completion: fn _context, _continuation -> :invalid_result end)

    log =
      capture_log(fn ->
        assert {:error, %OAuthError{error: :invalid_request}, _events} =
                 Token.issue(config, code_request(config, code))
      end)

    assert log =~ "authorization code completion callback returned an invalid result"
    refute log =~ "invalid_result"
    assert_spent_without_completion(family_id)
  end

  test "callback exceptions propagate and close an escaped continuation" do
    family_id = "family-callback-exception"
    code = issue_code(family_id)

    config =
      config(
        authorization_code_completion: fn _context, continuation ->
          send(self(), {:exception_continuation, continuation})
          raise "injected host callback failure"
        end
      )

    assert_raise RuntimeError, "injected host callback failure", fn ->
      Token.issue(config, code_request(config, code))
    end

    assert_receive {:exception_continuation, escaped}
    assert {:error, %OAuthError{error: :invalid_request}} = escaped.()
    assert_spent_without_completion(family_id)
  end

  test "a JTI-store exception rolls back an earlier logout-session write" do
    family_id = "family-jti-failure"

    code =
      issue_code(family_id, ["openid", "offline_access"],
        code_store: FailingAccessJTIStore,
        claims: %{"sid" => "sid-jti-failure"}
      )

    config = transactional_logout_config(FailingAccessJTIStore)

    assert_raise RuntimeError, "injected access JTI failure", fn ->
      Token.issue(config, code_request(config, code))
    end

    assert_receive {:completion_step, {:access_jti_failed, ^family_id, 1}, true}
    refute_received {:completion_step, {:refresh_insert, ^family_id, 0}, _active}
    refute_received {:completion_step, :code_finalization, _active}
    assert_spent_without_completion(family_id)
  end

  test "a finalization exception rolls back JTI, refresh, and logout-session writes" do
    family_id = "family-finalization-failure"

    code =
      issue_code(family_id, ["openid", "offline_access"],
        code_store: FailingFinalizationCodeStore,
        claims: %{"sid" => "sid-finalization-failure"}
      )

    config = transactional_logout_config(FailingFinalizationCodeStore)

    assert_raise RuntimeError, "injected code finalization failure", fn ->
      Token.issue(config, code_request(config, code))
    end

    assert_receive {:completion_step, {:refresh_insert, ^family_id, 0}, true}
    assert_receive {:completion_step, {:finalization_failed, true, 1, 1}, true}
    assert_spent_without_completion(family_id)
  end

  test "private context completes end-to-end through a custom Agent code store" do
    family_id = "family-agent-store"
    private_context = %{"security_epoch" => 91}

    code =
      issue_code(family_id, ["read"],
        code_store: AgentCodeStore,
        private_context: private_context
      )

    config =
      config(
        code_store: AgentCodeStore,
        refresh_store: nil,
        authorization_code_completion: fn context, continuation ->
          send(self(), {:agent_completion_context, context})
          continuation.()
        end
      )

    assert {:ok, response, _events} = Token.issue(config, code_request(config, code))
    assert_receive {:agent_completion_context, %{family_id: ^family_id, private_context: ^private_context}}
    refute claim!(response.access_token, "security_epoch")
    refute claim!(response.access_token, "private_context")

    entry = AgentCodeStore.entry(code)
    assert entry.consumed
    assert entry.consumed_success
    assert is_binary(entry.access_token_jti)
    assert entry.record.data.attesto_phoenix_private_context == private_context
  end

  defp config(overrides \\ []) do
    [
      issuer: "https://issuer.example",
      audience: "https://issuer.example",
      keystore: __MODULE__.Keystore,
      repo: TestRepo,
      load_client: fn _ -> {:error, :not_found} end,
      verify_client_secret: fn _client, _given -> false end,
      load_principal: fn _ -> {:error, :not_found} end,
      client_public?: fn client -> Map.get(client, :public?, false) end,
      client_id: fn client -> client.id end,
      authorize_scope: fn _client, requested -> {:ok, requested} end,
      principal_kinds: [@client_kind],
      build_principal: &principal/3,
      code_store: CompletionCodeStore,
      refresh_store: CompletionRefreshStore,
      issue_refresh_token?: fn _client, _scope -> true end
    ]
    |> Keyword.merge(overrides)
    |> Config.new()
  end

  defp principal(client, subject, scope) do
    %{
      kind: "client",
      sub: subject,
      scopes: scope,
      claims: %{"client_id" => client.id}
    }
  end

  defp issue_code(family_id, scope \\ ["offline_access"], opts \\ []) do
    private_context = Keyword.get(opts, :private_context)
    claims = Keyword.get(opts, :claims, %{})
    code_store = Keyword.get(opts, :code_store, CompletionCodeStore)

    {:ok, code} =
      AuthorizationCodePrivateContext.issue(
        code_store,
        %{
          client_id: "client-1",
          redirect_uri: @redirect_uri,
          scope: scope,
          subject: "oc_user-1",
          code_challenge: @code_challenge,
          code_challenge_method: "S256",
          family_id: family_id,
          claims: claims
        },
        private_context,
        []
      )

    code
  end

  defp transactional_logout_config(code_store) do
    config(
      code_store: code_store,
      authorization_code_completion: transactional_completion(self()),
      logout: [enabled: true],
      terminate_session: fn conn, _context -> {:ok, conn} end,
      logout_session_store: EctoLogoutSessionStore,
      client_frontchannel_logout_uri: fn _client -> "https://client.example/logout" end
    )
  end

  defp code_request(config, code) do
    %Request{
      config: config,
      client: @client,
      client_auth_method: :client_secret_basic,
      grant_type: "authorization_code",
      params: %{
        "code" => code,
        "code_verifier" => @code_verifier,
        "redirect_uri" => @redirect_uri
      },
      request_client_id: "client-1",
      sender_constraint_input: %{
        dpop_proof: nil,
        mtls_cert_der: nil,
        http_uri: "https://issuer.example/oauth/token",
        http_method: "POST"
      }
    }
  end

  defp transactional_completion(test_pid) do
    fn context, continuation ->
      send(test_pid, {:completion_context, context})

      result =
        TestRepo.transaction(fn ->
          Process.put(:authorization_code_completion_active, true)
          send(test_pid, {:completion_step, :transaction_started, true})

          try do
            case continuation.() do
              {:ok, _response, _events} = success -> success
              {:error, _error} = failure -> TestRepo.rollback(failure)
            end
          after
            Process.delete(:authorization_code_completion_active)
          end
        end)

      case result do
        {:ok, success} ->
          send(test_pid, :authorization_code_completion_committed)
          success

        {:error, {:error, _error} = failure} ->
          send(test_pid, :authorization_code_completion_rolled_back)
          failure

        {:error, reason} ->
          send(test_pid, :authorization_code_completion_rolled_back)
          {:error, reason}
      end
    end
  end

  defp authorization!(family_id), do: TestRepo.get_by!(Authorization, family_id: family_id)

  defp assert_spent_without_completion(family_id) do
    row = authorization!(family_id)
    assert row.consumed_at
    refute row.consumed_success
    refute row.access_token_jti
    assert TestRepo.aggregate(from(r in RefreshToken, where: r.family_id == ^family_id), :count) == 0
    assert TestRepo.aggregate(LogoutSession, :count) == 0
  end

  defp completion_active?, do: Process.get(:authorization_code_completion_active) == true

  defp claim!(jwt, key) when is_binary(jwt) do
    claims!(jwt)[key]
  end

  defp claims!(jwt) when is_binary(jwt) do
    [_header, payload | _] = String.split(jwt, ".")
    {:ok, json} = Base.url_decode64(payload, padding: false)
    JSON.decode!(json)
  end
end
