defmodule AttestoPhoenix.AuthorizationCodePrivateContext do
  @moduledoc false

  @behaviour Attesto.CodeStore

  alias Attesto.AuthorizationCode

  @operation_key {__MODULE__, :operation}
  @captured_context_key {__MODULE__, :captured_context}
  @data_key :attesto_phoenix_private_context

  @spec issue(module(), map(), map() | nil, keyword()) ::
          {:ok, String.t()} | {:error, AuthorizationCode.issue_error()}
  def issue(store, attrs, nil, opts), do: AuthorizationCode.issue(store, attrs, opts)

  def issue(store, attrs, private_context, opts)
      when is_atom(store) and is_map(attrs) and is_map(private_context) and is_list(opts) do
    with_operation({:issue, store, private_context}, fn ->
      AuthorizationCode.issue(__MODULE__, attrs, opts)
    end)
  end

  @spec redeem(module(), String.t(), map(), keyword()) ::
          {{:ok, AuthorizationCode.Grant.t()} | {:error, AuthorizationCode.redeem_error()}, map() | nil}
  def redeem(store, code, params, opts \\ [])
      when is_atom(store) and is_binary(code) and is_map(params) and is_list(opts) do
    with_operation({:redeem, store}, fn ->
      result = AuthorizationCode.redeem(__MODULE__, code, params, opts)
      private_context = if match?({:ok, _grant}, result), do: Process.get(@captured_context_key)
      {result, private_context}
    end)
  end

  @impl Attesto.CodeStore
  def put(%{data: data} = record) when is_map(data) do
    {:issue, store, private_context} = Process.get(@operation_key)
    store.put(%{record | data: Map.put(data, @data_key, private_context)})
  end

  @impl Attesto.CodeStore
  def take(code_hash) when is_binary(code_hash) do
    {:redeem, store} = Process.get(@operation_key)

    case store.take(code_hash) do
      {:ok, %{data: data} = record} when is_map(data) ->
        {private_context, grant_data} = Map.pop(data, @data_key)
        Process.put(@captured_context_key, private_context)
        {:ok, %{record | data: grant_data}}

      other ->
        other
    end
  end

  defp with_operation(operation, fun) do
    previous_operation = Process.get(@operation_key)
    previous_context = Process.get(@captured_context_key)
    Process.put(@operation_key, operation)
    Process.delete(@captured_context_key)

    try do
      fun.()
    after
      restore_process_value(@operation_key, previous_operation)
      restore_process_value(@captured_context_key, previous_context)
    end
  end

  defp restore_process_value(key, nil), do: Process.delete(key)
  defp restore_process_value(key, value), do: Process.put(key, value)
end
