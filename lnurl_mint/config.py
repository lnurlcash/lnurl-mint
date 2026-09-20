import os
from datetime import date
from typing import Literal
from urllib.parse import urlparse

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from .node import LightningBackendConfig


class Settings(BaseSettings):
    # env_file is overridable via LNURL_MINT_ENV_FILE (pointed at a
    # nonexistent path by tests/conftest.py) so the test suite never picks
    # up a developer's own .env in this same directory (e.g. real
    # FUNDINGSOURCE_* credentials for local testing against lnurl_server's
    # regtest nodes) - a real process env var can't cleanly cancel out a
    # dotenv value (env_ignore_empty only skips *that* source, falling
    # through to the next-lowest, i.e. right back to the dotenv file), so
    # the file itself must not be read at all instead.
    model_config = SettingsConfigDict(
        env_file=os.environ.get("LNURL_MINT_ENV_FILE", ".env"), env_file_encoding="utf-8", extra="ignore"
    )

    # this mint's own funding source, configured once by the operator - used
    # to create the invoices that mint bearer notes and to pay the invoices
    # that melt them, and to sign notes for LUD-25's optional Offline
    # verification via the node's own signmessage RPC (see signing.py) -
    # there's no separate setting for that, it's simply unavailable without
    # a funding source. Only the credential for the chosen backend is
    # required (macaroon for lnd, rune for cln, mnemonic for spark); the
    # others are ignored.
    fundingsource_backend: Literal["lnd", "cln", "spark"] | None = None
    fundingsource_url: str | None = None
    fundingsource_macaroon: SecretStr | None = None
    fundingsource_rune: SecretStr | None = None
    # path to a self-signed TLS cert to verify the funding source against -
    # both lnd's and cln's REST APIs are commonly self-signed. Leave unset if
    # it's fronted by a reverse proxy with a real certificate.
    fundingsource_cert_path: str | None = None

    # spark (FUNDINGSOURCE_BACKEND=spark, see lnurl_mint/spark.py): the
    # BIP39 mnemonic of the mint's breez-sdk-spark wallet - the wallet's
    # entire key material, treat like a hot wallet seed. The Breez API
    # key the SDK's services (notably the mainnet SSP) require, from
    # https://breez.technology/request-api-key. The SDK keeps its own
    # sqlite store of payments and claims; it defaults to a
    # spark-wallet/ directory next to DATABASE_PATH and must never be
    # shared by two processes, same rule as DATABASE_PATH itself.
    # sync_interval bounds how long after a payment lands that settlement
    # detection can first notice (see spark.py). The optional
    # breez-sdk-spark dependency is needed to use any of this
    # (`uv sync --extra spark`).
    fundingsource_spark_mnemonic: SecretStr | None = None
    fundingsource_spark_api_key: SecretStr | None = None
    fundingsource_spark_network: Literal["mainnet", "regtest"] = "mainnet"
    fundingsource_spark_storage_dir: str | None = None
    fundingsource_spark_sync_interval_secs: int = Field(default=15, ge=1)
    fundingsource_spark_account_number: int | None = None
    # how often (seconds) to re-probe the funding source in the background
    # after boot, once a backend is configured - the one-shot check at
    # startup (see server.py's lifespan) only catches a connection problem
    # that already existed at boot; this catches one that develops later,
    # or a flaky one boot happened to catch mid-recovery. Only ever logs on
    # a state transition (became unreachable / recovered), never every tick.
    # ge=1: 0 would busy-loop getinfo against the node (server.py's monitor
    # sleeps exactly this between probes). For the spark backend this
    # interval is also the connectivity-probe cadence (see spark.py's
    # _remote_probe): every healthy tick leaves one expiring 1-sat invoice
    # at the SSP, so raise it if that cadence ever matters to you.
    funding_source_health_check_interval_seconds: int = Field(default=60, ge=1)

    # bounds on the value of a single minted note (LUD-06 min/maxSendable) -
    # ordered relative to each other (validated below, after both are read)
    min_sendable_msat: int = Field(default=10_000, ge=1)
    max_sendable_msat: int = Field(default=1_000_000_000, ge=1)

    # LUD-25's optional mint fee: withheld from every minted note's value
    # (a flat base_fee_msat plus fee_percent_ppm parts-per-million of the
    # amount paid), meant to cover the routing cost of eventually paying
    # the note back out on melt. Advertised in /p/cb's payRequest metadata
    # (see router.get_lnaddress) so a wallet can warn the payer up front -
    # omitted from metadata entirely (assumed fee-free per spec) when both
    # are zero. fee_percent_ppm is bounded well below 1_000_000 (100%): at
    # or above that the fee can never leave a positive net amount, which
    # sends router._min_sendable_msat's walk into a non-terminating loop -
    # and even merely close to it, each lnaddress request burns millions of loop
    # iterations of CPU. 100_000 (10%) keeps the walk under ~100 steps.
    base_fee_msat: int = Field(default=1000, ge=0)
    fee_percent_ppm: int = Field(default=0, ge=0, le=100_000)

    # floor on a note's value net of the mint fee (not on `amount` itself,
    # which min_sendable_msat already bounds) - guards against minting
    # dust-value notes not worth the routing cost of ever melting them.
    # /p/cb rejects an `amount` that would net less than this after fees.
    min_mint_msat: int = Field(default=10_000, ge=0)

    # cap on the number of k1s a single /w/cb request (melt/rotate/split/
    # merge) may name - well above any real wallet's outstanding note count
    # (one holding more consolidates across multiple requests), just to
    # bound the DB lookups - and query-string size - a single
    # unauthenticated request can force
    max_k1s: int = 100

    # winds this mint down: /p/cb (minting) and /w/cb's split branch (which,
    # like minting, grows the number of outstanding notes) both reject
    # outright while this is on - rotate, merge, and melt are all left
    # alone, since none of them increases this mint's outstanding liability
    # and an operator sunsetting a mint still needs holders to be able to
    # consolidate and redeem their notes. Off by default.
    sunset_mint: bool = False

    # advance warning of a planned shutdown: an ISO-8601 date (e.g.
    # "2026-12-31") an operator sets to tell holders when this mint intends
    # to sunset, so they have time to melt or migrate their notes before
    # that day arrives - rather than only finding out once sunset_mint is
    # already on and minting has already stopped. Purely informational: it
    # does not itself disable anything (see sunset_mint above for what
    # actually does), an operator still flips that separately, whenever
    # they're ready. Advertised on the mint-address discovery endpoint
    # (router.get_mint_address/_mint_address_response) and the frontend
    # one-pager (frontend._sunset_warning). None (the default) shows
    # nothing - most mints never plan to sunset at all.
    sunset_date: date | None = None

    database_path: str = "mint.db"

    # asset profile, part 1 of 3: a mint that never pays out. When off,
    # /w/cb rejects any request carrying `pr` before the invoice is even
    # decoded, so mark_pending, _melt_pay, reconcile_pending_melts and melt
    # verify are never reached. Notes minted here are still LUD-25 notes -
    # rotate/split/merge, offline certificates and internal transfers all
    # work - they just can never be turned back into sats: the mint payment
    # is the operator's income, not a balance held for the holder. This
    # deliberately gives up LUD-03 backward compatibility (a wallet that
    # does not know this mint will try to melt and get an error), so an
    # operator should write down what these notes ARE before inviting
    # anyone to hold one. Same off-switch convention as verify_enabled;
    # nothing is advertised while on, since a paying-out mint is the
    # normal case. On by default.
    melt_enabled: bool = True

    # LUD-21 (optional): serve /verify/{payment_hash} and advertise a
    # `verify` URL in /p/cb's (and a melt's) response, so a wallet with no
    # node of its own can poll whether its invoice settled. Once settled,
    # the response's `preimage` IS the freshly minted bearer note's spend
    # secret (see router.verify_invoice) - served to ANY holder of the
    # payment hash, which travels inside the invoice itself, so a wallet
    # MUST rotate the note immediately after claiming it, and an operator
    # unwilling to serve spend secrets to any invoice holder should turn
    # this off. Unlike the
    # ecosystem's usual convention, false here disables the endpoint
    # entirely (404), not just its advertisement - precisely because the
    # preimage is a bearer secret here, not mere proof of payment.
    verify_enabled: bool = True

    # LUD-25 Part 2 (optional): serve POST/DELETE /p/{username}, letting a
    # WALLET claim a Lightning Address username against its own cx1 branch
    # (see router.upsert_registered_username) - this mint then auto-mints
    # for every payment it receives there, no per-payment WALLET
    # involvement needed.
    # Off disables the endpoint entirely (404), same off-switch convention
    # as verify_enabled, for an operator who wants this mint to stay a
    # single fixed identity, never a multi-tenant one.
    username_registration_enabled: bool = True

    # NIP-05 (optional): serve GET /.well-known/nostr.json (router.get_nip05)
    # and accept the optional `npub` argument to POST /p/{username} (see
    # router.upsert_registered_username) - independent of
    # username_registration_enabled above, which only gates whether a
    # username can be claimed at all: an operator can allow registration
    # while keeping every registrant's Nostr identity private (this off,
    # that on), or vice versa refuse new registrations while still resolving
    # npubs already on file (this on, that off). Off disables the endpoint
    # entirely (404), same off-switch convention as verify_enabled/
    # username_registration_enabled, and rejects an `npub` argument outright
    # rather than silently storing one nothing will ever resolve. Unrelated
    # to nostr_key below - that one gates NIP-57 zap receipts, a mint can
    # offer either, both, or neither.
    nip05_enabled: bool = True

    # NIP-57 zaps (optional): this mint's own Nostr key, 32 bytes of hex.
    # Set, a registered username's payRequest advertises `allowsNostr` and
    # `nostrPubkey`, /p/cb takes a kind 9734 zap request and commits the
    # invoice to it, and once the invoice settles the mint publishes the
    # kind 9735 receipt (see nostr.py). Publish-only: the mint subscribes
    # to nothing. Needs an lnd or cln funding source, the two that let a
    # caller set an invoice's description hash. Unset, zaps are off.
    nostr_key: SecretStr | None = None
    # relays every receipt is published to, comma separated, on top of the
    # ones the zap request itself names
    nostr_relays: str = ""
    # how often settled zap invoices are looked for and their receipts
    # published; a zapping client waits on the receipt, so keep it short
    zap_poll_interval_seconds: int = Field(default=5, ge=1)

    # the one-pager frontend (GET /)
    title: str = "lnurl-mint"
    description: str = "A minimal lnurlcash mint - pay the QR code to mint a Lightning bearer note."
    # public base URL of this mint (e.g. https://mint.example) - used for the
    # QR code's LNURL, the lightning address domain, and the LUD-16 metadata
    # identifier. Required, not derived from a request's own Host header:
    # trusting that would let whoever sends the request (or, behind a cache
    # that doesn't vary on Host, an attacker poisoning a cached response for
    # other visitors) control the callback/withdrawLink URLs handed back to
    # a wallet.
    base_url: str
    # this mint's Tor hidden service address (e.g. http://<v3-address>.onion),
    # if it has one - advertised on the frontend one-pager as an alternative
    # way to reach it (see frontend.py). If a wallet is actually connecting
    # through this address (the request's own Host matches its hostname),
    # public_base_url prefers it over base_url, so the LNURL/callback URLs
    # in that response stay reachable over Tor - a fixed clearnet base_url
    # would otherwise leak into a Tor visitor's QR code and break payment
    # for them, since the callback would point back at a host Tor can't
    # reach (or that defeats the point of using Tor to begin with).
    onion_url: str | None = None
    # LUD-16: the mint is payable at {username}@{base_url host}
    username: str = "mint"

    # every route that needs to embed this mint's own hostname somewhere
    # (defaultDescription, the lightning address, ...) must derive it from
    # base_url/onion_url, never a request's own Host header - same reason
    # base_url itself is required rather than request-derived. Validated
    # once here, at startup, rather than falling back to something
    # request-derived per call site if parsing ever failed.
    @field_validator("base_url")
    @classmethod
    def _base_url_needs_a_hostname(cls, value: str) -> str:
        if not urlparse(value).hostname:
            raise ValueError(f"BASE_URL {value!r} has no hostname.")
        return value

    @field_validator("onion_url")
    @classmethod
    def _onion_url_needs_a_hostname(cls, value: str | None) -> str | None:
        if value is not None and not urlparse(value).hostname:
            raise ValueError(f"ONION_URL {value!r} has no hostname.")
        return value

    @model_validator(mode="after")
    def _sendable_bounds_are_ordered(self) -> "Settings":
        """min_sendable_msat <= max_sendable_msat - inverted bounds would
        make every /p/cb amount reject (too low AND too high at once),
        better caught here at startup than by a wallet's first attempt."""
        if self.min_sendable_msat > self.max_sendable_msat:
            raise ValueError(
                f"MIN_SENDABLE_MSAT ({self.min_sendable_msat}) exceeds MAX_SENDABLE_MSAT ({self.max_sendable_msat})."
            )
        return self

    @field_validator("nostr_key")
    @classmethod
    def _nostr_key_is_32_bytes_of_hex(cls, value: SecretStr | None) -> SecretStr | None:
        if value is not None:
            secret = value.get_secret_value()
            if len(secret) != 64 or any(c not in "0123456789abcdefABCDEF" for c in secret):
                raise ValueError("NOSTR_KEY must be 32 bytes of hex.")
        return value

    def nostr_pubkey(self) -> str | None:
        from .nostr import pubkey_of

        return pubkey_of(self.nostr_key.get_secret_value()) if self.nostr_key else None

    def nostr_relay_list(self) -> list[str]:
        return [r.strip() for r in self.nostr_relays.split(",") if r.strip()]

    def public_base_url(self, request_base_url: str) -> str:
        if self.onion_url:
            request_host = urlparse(request_base_url).hostname or ""
            onion_host = urlparse(self.onion_url).hostname or ""
            if request_host and request_host == onion_host:
                return self.onion_url.rstrip("/")
        return self.base_url.rstrip("/")

    def public_base_url_and_host(self, request_base_url: str) -> tuple[str, str]:
        """(public_base_url(...), its hostname) - for the routes that need
        both. The hostname is guaranteed present: base_url/onion_url are
        validated above to have one."""
        base = self.public_base_url(request_base_url)
        host = urlparse(base).hostname
        assert host is not None
        return base, host

    def funding_source(self) -> LightningBackendConfig:
        return LightningBackendConfig(
            backend=self.fundingsource_backend,
            url=self.fundingsource_url,
            macaroon=self.fundingsource_macaroon,
            rune=self.fundingsource_rune,
            cert_path=self.fundingsource_cert_path,
            spark_mnemonic=self.fundingsource_spark_mnemonic,
            spark_api_key=self.fundingsource_spark_api_key,
            spark_network=self.fundingsource_spark_network,
            spark_storage_dir=self.fundingsource_spark_storage_dir
            or os.path.join(os.path.dirname(os.path.abspath(self.database_path)), "spark-wallet"),
            spark_sync_interval_secs=self.fundingsource_spark_sync_interval_secs,
            spark_account_number=self.fundingsource_spark_account_number,
        )


settings = Settings()
