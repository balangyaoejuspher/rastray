class Rastray < Formula
  desc "Blazing-fast static analysis for security, dependencies, and performance"
  homepage "https://github.com/balangyaoejuspher/rastray"
  version "0.11.0"
  license any_of: ["MIT", "Apache-2.0"]

  on_macos do
    on_arm do
      url "https://github.com/balangyaoejuspher/rastray/releases/download/v#{version}/rastray-v#{version}-aarch64-apple-darwin.tar.gz"
      sha256 "8de0fb9f543a87d53345323a7f9cff3bb9676e2df8304f63412c271dd68d3fb5"
    end
    on_intel do
      url "https://github.com/balangyaoejuspher/rastray/releases/download/v#{version}/rastray-v#{version}-x86_64-apple-darwin.tar.gz"
      sha256 "aef524f4338a05b6f32777d46f62f7a2ba237974cd4e25b2c4999a8b9ed1e80f"
    end
  end

  on_linux do
    on_intel do
      url "https://github.com/balangyaoejuspher/rastray/releases/download/v#{version}/rastray-v#{version}-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "28e58c577e99f2a28518d09285154c81b5fb725521c0ccf5a1affbfc6b108640"
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
