<p align="center"><a href="https://www.localzet.com" target="_blank">
  <img src="https://static.zorin.space/media/logos/ZorinProjectsSP.svg" width="400">
</a></p>

<p align="center">
  <a href="https://packagist.org/packages/localzet/webauthn">
  <img src="https://img.shields.io/packagist/dt/localzet/webauthn?label=%D0%A1%D0%BA%D0%B0%D1%87%D0%B8%D0%B2%D0%B0%D0%BD%D0%B8%D1%8F" alt="Скачивания">
</a>
  <a href="https://github.com/localzet/WebAuthn">
  <img src="https://img.shields.io/github/commit-activity/t/localzet/WebAuthn?label=%D0%9A%D0%BE%D0%BC%D0%BC%D0%B8%D1%82%D1%8B" alt="Коммиты">
</a>
  <a href="https://packagist.org/packages/localzet/webauthn">
  <img src="https://img.shields.io/packagist/v/localzet/webauthn?label=%D0%92%D0%B5%D1%80%D1%81%D0%B8%D1%8F" alt="Версия">
</a>
  <a href="https://packagist.org/packages/localzet/webauthn">
  <img src="https://img.shields.io/packagist/dependency-v/localzet/webauthn/php?label=PHP" alt="Версия PHP">
</a>
  <a href="https://github.com/localzet/WebAuthn">
  <img src="https://img.shields.io/github/license/localzet/WebAuthn?label=%D0%9B%D0%B8%D1%86%D0%B5%D0%BD%D0%B7%D0%B8%D1%8F" alt="Лицензия">
</a>
</p>


## Security and production status

This library currently **does not support live FIDO Metadata Service imports**. The previous implementation imported attestation certificates from an **unverified JWT** and is intentionally disabled until MDS JWT signatures, pinned trust anchors and update semantics are implemented and tested. Bundled local certificates are still loaded, but their provenance and freshness need an independent review before relying on attestation trust.

Always preserve a single-use challenge per credential ceremony and store it server-side for verification. Allowed origins must be HTTPS (except localhost) and their hostnames must match the RP ID exactly or end in `.<rp-id>`.

Run `php tests/security.php` after `composer install` to verify the basic trust boundary checks. A complete WebAuthn conformance suite is still required before production deployment.
