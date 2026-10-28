# Homebrew cask for the macOS app: `brew install --cask yashagldit/thumbdesk/thumbdesk`.
# A template. The release workflow (.github/workflows/release-host-agent.yml)
# fills in `version` and `sha256` from each full release's notarized disk image
# and commits it to the tap, yashagldit/homebrew-thumbdesk, as Casks/thumbdesk.rb.
#
# A cask, not a formula, because on a Mac the agent is Thumbdesk.app: the app
# is the only copy, and the `thumbdesk` command, and `pocketshell` (its former
# name), are links into it, so `brew uninstall --cask thumbdesk` removes the
# agent itself. The release URL keeps the repository the agents update from
# (yashagldit/PocketShell).
cask "thumbdesk" do
  version "REPLACE_WITH_RELEASE_VERSION"
  sha256 "REPLACE_WITH_DMG_SHA256"

  url "https://github.com/yashagldit/PocketShell/releases/download/v#{version}/Thumbdesk-v#{version}-aarch64-apple-darwin.dmg",
      verified: "github.com/yashagldit/PocketShell/"
  name "Thumbdesk"
  desc "Terminal, files and screen access to this Mac from the Thumbdesk mobile app"
  homepage "https://thumbdesk.com"

  depends_on arch: :arm64
  depends_on macos: ">= :ventura"

  app "Thumbdesk.app"
  binary "#{appdir}/Thumbdesk.app/Contents/MacOS/thumbdesk"
  binary "#{appdir}/Thumbdesk.app/Contents/MacOS/thumbdesk", target: "pocketshell"

  # The LaunchAgent under its current label, and under the one an agent from
  # before the rename installed.
  uninstall launchctl: [
    "com.thumbdesk.host-agent",
    "com.pocketshell.host-agent",
  ]

  zap trash: [
    "~/.thumbdesk",
    "~/.pocketshell",
    "~/Library/LaunchAgents/com.thumbdesk.host-agent.plist",
    "~/Library/LaunchAgents/com.pocketshell.host-agent.plist",
    "~/Library/Logs/thumbdesk-host-agent.log",
    "~/Library/Logs/pocketshell-host-agent.log",
  ]
end
