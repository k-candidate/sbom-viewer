(function () {
  const releaseUrl = "https://github.com/k-candidate/sbom-viewer/releases/latest";
  const apiUrl = "https://api.github.com/repos/k-candidate/sbom-viewer/releases/latest";
  const status = document.getElementById("release-status");
  const cards = document.querySelectorAll("[data-platform]");

  const matchers = {
    installer: {
      "macos-arm64": /^sbom-viewer-.+-macos-arm64\.dmg$/,
      "macos-intel": /^sbom-viewer-.+-macos-intel\.dmg$/,
      "windows-x64": /^sbom-viewer-.+-windows-x64\.msi$/,
      "windows-arm64": /^sbom-viewer-.+-windows-arm64\.msi$/,
      "linux-x64": /^sbom-viewer_.+_amd64\.deb$/,
      "linux-arm64": /^sbom-viewer_.+_arm64\.deb$/,
    },
    portable: {
      "macos-arm64": /^sbom-viewer-.+-macos-arm64\.zip$/,
      "macos-intel": /^sbom-viewer-.+-macos-intel\.zip$/,
      "windows-x64": /^sbom-viewer-.+-windows-x64\.zip$/,
      "windows-arm64": /^sbom-viewer-.+-windows-arm64\.zip$/,
      "linux-x64": /^sbom-viewer-.+-linux-x64\.tar\.gz$/,
      "linux-arm64": /^sbom-viewer-.+-linux-arm64\.tar\.gz$/,
    },
  };

  function setStatus(message) {
    if (status) {
      status.textContent = message;
    }
  }

  function findAsset(assets, platform, kind) {
    const matcher = matchers[kind] && matchers[kind][platform];
    if (!matcher) {
      return null;
    }

    return assets.find((asset) => matcher.test(asset.name));
  }

  function wireDownloads(release) {
    const assets = release.assets || [];

    cards.forEach((card) => {
      const platform = card.dataset.platform;
      let missing = true;

      card.querySelectorAll("[data-kind]").forEach((button) => {
        const asset = findAsset(assets, platform, button.dataset.kind);
        if (asset) {
          button.href = asset.browser_download_url;
          button.setAttribute("download", "");
          button.title = asset.name;
          missing = false;
        }
      });

      card.classList.toggle("missing", missing);
    });

    const releaseName = release.name || release.tag_name;
    setStatus("Latest release: " + releaseName);
  }

  fetch(apiUrl, { headers: { Accept: "application/vnd.github+json" } })
    .then((response) => {
      if (!response.ok) {
        throw new Error("GitHub returned " + response.status);
      }
      return response.json();
    })
    .then(wireDownloads)
    .catch(() => {
      setStatus("Download buttons currently point to the latest GitHub release.");
      cards.forEach((card) => {
        card.querySelectorAll("[data-kind]").forEach((button) => {
          button.href = releaseUrl;
        });
      });
    });
})();
