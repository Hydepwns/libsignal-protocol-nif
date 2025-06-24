defmodule LibsignalProtocol.MixProject do
  use Mix.Project

  def project do
    [
      app: :libsignal_protocol,
      version: "0.1.0",
      elixir: "~> 1.15",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      test_coverage: [tool: ExCoveralls, output: "tmp/cover"],
      preferred_cli_env: [
        coveralls: :test,
        "coveralls.detail": :test,
        "coveralls.post": :test,
        "coveralls.html": :test,
        "coveralls.github": :test
      ],
      docs: [output: "tmp/doc"],
      aliases: aliases()
    ]
  end

  def application do
    [
      extra_applications: [:logger]
    ]
  end

  defp deps do
    [
      {:ex_doc, "~> 0.31", only: :dev, runtime: false},
      {:excoveralls, "~> 0.18", only: :test},
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false},
      {:dialyxir, "~> 1.3", only: [:dev], runtime: false}
    ]
  end

  # Ensure the NIF is built and cleaned like in rebar.config
  # The NIF is expected at priv/libsignal_protocol_nif.so
  defp aliases do
    [
      compile: ["cmd make -C ../../c_src build", "compile"],
      clean: ["cmd make -C ../../c_src clean", "clean"]
    ]
  end
end 