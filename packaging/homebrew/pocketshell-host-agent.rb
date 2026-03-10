class PocketshellHostAgent < Formula
  desc "PocketShell host agent CLI and daemon"
  homepage "https://example.com/pocketshell"
  url "https://example.com/pocketshell-host-agent-0.1.0.tar.gz"
  sha256 "REPLACE_WITH_RELEASE_SHA256"
  license "MIT"

  depends_on "rust" => :build

  def install
    system "cargo", "install", *std_cargo_args(path: "crates/host-agent")
  end

  service do
    run [opt_bin/"myapp", "daemon", "run"]
    keep_alive true
    log_path var/"log/pocketshell-host-agent.log"
    error_log_path var/"log/pocketshell-host-agent.log"
  end

  test do
    assert_match "PocketShell host agent", shell_output("#{bin}/myapp --help")
  end
end
