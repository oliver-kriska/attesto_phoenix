defmodule AttestoPhoenix.TestRepo.Migrations.AddAuthorizationCodePrivateContext do
  @moduledoc false

  use Ecto.Migration

  def change do
    alter table(:attesto_authorization_codes) do
      add(:private_context, :map)
    end
  end
end
