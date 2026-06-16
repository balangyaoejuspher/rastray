class Rastray < Formula
  desc "Blazing-fast static analysis for security, dependencies, and performance"
  homepage "https://github.com/balangyaoejuspher/rastray"
  version "0.13.0"
  license any_of: ["MIT", "Apache-2.0"]

  on_macos do
    on_arm do
      url "https://github.com/balangyaoejuspher/rastray/releases/download/v#{version}/rastray-v#{version}-aarch64-apple-darwin.tar.gz"
      sha256 "b5e58fab405dec9df6a630aa4b68813ded7950ee0d67851ed80913779e5a9c15"
    end
    on_intel do
      url "https://github.com/balangyaoejuspher/rastray/releases/download/v#{version}/rastray-v#{version}-x86_64-apple-darwin.tar.gz"
      sha256 "696f69699cf3f2487711f3484e698a19ca9426cc6a71cc297534b8311f2cd0dc"
    end
  end

  on_linux do
    on_intel do
      url "https://github.com/balangyaoejuspher/rastray/releases/download/v#{version}/rastray-v#{version}-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "3df2221da9d4e6f864197b2bed664eeaad202d0bbb637e98b039ee81cb2873a5"
    end
  end

  def install
    bin.install "rastray"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/rastray --version")
    (testpath/"sample.py").write <<~PY
      import os
      os.system("echo hello")
    PY
    system "#{bin}/rastray", testpath.to_s, "--fail-on", "never"
  end
end
