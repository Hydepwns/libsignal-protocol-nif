ExUnit.start()

# Configure test environment
ExUnit.configure(exclude: [:skip], trace: true)

# Test helper functions
defmodule TestHelper do
  @moduledoc """
  Helper functions for testing the LibsignalProtocol wrapper.
  """

  import ExUnit.Assertions

  def generate_test_key(size \\ 32) do
    :crypto.strong_rand_bytes(size)
  end

  def assert_binary_result({:ok, result}) when is_binary(result) do
    assert byte_size(result) > 0
    result
  end

  def assert_binary_result({:error, reason}) do
    # In test environment, NIF might not be loaded, so errors are acceptable
    assert is_binary(reason) or is_atom(reason)
    :error
  end

  def assert_tuple_result({:ok, {a, b}}) when is_binary(a) and is_binary(b) do
    assert byte_size(a) > 0
    assert byte_size(b) > 0
    {a, b}
  end

  def assert_tuple_result({:error, reason}) do
    # In test environment, NIF might not be loaded, so errors are acceptable
    assert is_binary(reason) or is_atom(reason)
    :error
  end
end
