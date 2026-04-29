---
layout: default
title: SBOM Viewer
description: Desktop GUI for viewing Software Bill of Materials in SPDX, CycloneDX, and SWID formats.
---

<section class="intro">
  <img class="app-logo" src="{{ '/assets/img/sbom-viewer.png' | relative_url }}" alt="SBOM Viewer logo">
  <div>
    <p class="lede">
      SBOM Viewer is a desktop app for opening Software Bill of Materials files and exploring their components,
      dependencies, and metadata without turning every inspection into a text-search expedition.
    </p>
    <p>
      It auto-detects SPDX, CycloneDX, and SWID documents, then presents the data in searchable tabs with a component
      details panel and resizable columns.
    </p>
  </div>
</section>

## Downloads

<p id="release-status" class="release-status" aria-live="polite">
  Loading the latest release...
</p>

<div class="download-grid" id="downloads">
  <section class="download-column" aria-label="macOS downloads">
    <h3>macOS</h3>
    <article class="download-card" data-platform="macos-arm64">
      <h4>Apple Silicon</h4>
      <p>For Macs with Apple Silicon processors.</p>
      <div class="download-actions">
        <a class="btn download-button" data-kind="installer" href="https://github.com/k-candidate/sbom-viewer/releases/latest">DMG</a>
        <a class="btn download-button" data-kind="portable" href="https://github.com/k-candidate/sbom-viewer/releases/latest">ZIP</a>
      </div>
    </article>

    <article class="download-card" data-platform="macos-intel">
      <h4>Intel</h4>
      <p>For Intel-based Macs.</p>
      <div class="download-actions">
        <a class="btn download-button" data-kind="installer" href="https://github.com/k-candidate/sbom-viewer/releases/latest">DMG</a>
        <a class="btn download-button" data-kind="portable" href="https://github.com/k-candidate/sbom-viewer/releases/latest">ZIP</a>
      </div>
    </article>
  </section>

  <section class="download-column" aria-label="Windows downloads">
    <h3>Windows</h3>
    <article class="download-card" data-platform="windows-x64">
      <h4>x64</h4>
      <p>For most Windows PCs.</p>
      <div class="download-actions">
        <a class="btn download-button" data-kind="installer" href="https://github.com/k-candidate/sbom-viewer/releases/latest">MSI</a>
        <a class="btn download-button" data-kind="portable" href="https://github.com/k-candidate/sbom-viewer/releases/latest">ZIP</a>
      </div>
    </article>

    <article class="download-card" data-platform="windows-arm64">
      <h4>ARM64</h4>
      <p>For Windows on ARM devices.</p>
      <div class="download-actions">
        <a class="btn download-button" data-kind="installer" href="https://github.com/k-candidate/sbom-viewer/releases/latest">MSI</a>
        <a class="btn download-button" data-kind="portable" href="https://github.com/k-candidate/sbom-viewer/releases/latest">ZIP</a>
      </div>
    </article>
  </section>

  <section class="download-column" aria-label="Linux downloads">
    <h3>Linux</h3>
    <article class="download-card" data-platform="linux-x64">
      <h4>x64</h4>
      <p>For Debian-based distributions on amd64.</p>
      <div class="download-actions">
        <a class="btn download-button" data-kind="installer" href="https://github.com/k-candidate/sbom-viewer/releases/latest">DEB</a>
        <a class="btn download-button" data-kind="portable" href="https://github.com/k-candidate/sbom-viewer/releases/latest">TAR.GZ</a>
      </div>
    </article>

    <article class="download-card" data-platform="linux-arm64">
      <h4>ARM64</h4>
      <p>For Debian-based distributions on arm64.</p>
      <div class="download-actions">
        <a class="btn download-button" data-kind="installer" href="https://github.com/k-candidate/sbom-viewer/releases/latest">DEB</a>
        <a class="btn download-button" data-kind="portable" href="https://github.com/k-candidate/sbom-viewer/releases/latest">TAR.GZ</a>
      </div>
    </article>
  </section>
</div>

## Project Links

- [Source code](https://github.com/k-candidate/sbom-viewer)
- [Latest GitHub release](https://github.com/k-candidate/sbom-viewer/releases/latest)
- [Author blog](https://k-candidate.github.io/)

<script src="{{ '/assets/js/downloads.js' | relative_url }}"></script>
